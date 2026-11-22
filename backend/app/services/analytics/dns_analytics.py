"""DNS transaction matching, response-time and failure analytics.

A *transaction* is one query (possibly retransmitted) and its response. Matching key:
(client ip, client port, server ip, server port, DNS transaction id, transport). A
response is the packet with QR=1 and its client is the destination; for TCP the same
4-tuple identifies the connection. Transport is part of the key so a UDP query is never
matched to a TCP response (a truncated UDP answer retried over TCP is a separate transaction).

Matching rules
- Same key seen again while a transaction is pending and within ``retry_window_seconds`` is a
  query retransmission (counted on the transaction, not as a new query). Beyond the window
  the old transaction is left unanswered and a new one starts (the id was reused).
- A response matches a pending transaction when it arrives no earlier than the query and
  within ``match_window_seconds``, and (if both carry questions) its first question equals the
  query's (case-insensitive name and type). Otherwise it is an *unmatched response*.
- A second response for an already answered transaction is a ``duplicate_response`` and is
  ignored for latency and failure rates.
- TCP segments flagged as TCP retransmissions are skipped so a retransmitted segment is not
  mistaken for a DNS retry. DNS over TCP is recognised only when the whole message is in one
  segment (a message split over several segments is not reassembled).
- Messages with several questions are one transaction; its name/type fields hold the first
  question and ``questions`` holds all (at most 8 are recorded).

Latency: ``latency_ms`` = first query transmission to response (what the client waited);
``latency_from_last_query_ms`` = last (re)transmission to response (server/path time).

Failure rates: denominators count *responses observed* (answered + unmatched responses,
duplicates excluded), so unanswered queries never inflate or deflate them.
- ``error_response_rate``: responses with RCODE != NOERROR (includes NXDOMAIN).
- ``server_failure_rate``: responses with RCODE other than NOERROR and NXDOMAIN
  (FORMERR, SERVFAIL, NOTIMP, REFUSED, ...). NXDOMAIN is a legitimate "no such name" answer.

Unanswered queries are tracked separately. One is ``inferred_timeout`` only if the capture
continued at least ``timeout_seconds`` after its last transmission; otherwise it is
``indeterminate`` because the response may simply fall after the capture ended. Even an
inferred timeout is an inference: the response may have bypassed the capture point.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from .common import distribution, histogram, iso, ms, qtype_name, ratio, rcode_name

MAX_QUESTIONS = 8
LATENCY_EDGES = [0, 1, 5, 20, 50, 100, 250, 500, 1000, 5000]  # ms
_RECENT_DONE = 4096


@dataclass(slots=True)
class DnsConfig:
    timeout_seconds: float = 5.0
    retry_window_seconds: float = 30.0
    match_window_seconds: float = 60.0


@dataclass(slots=True)
class Txn:
    id: int
    transport: str
    client_ip: str
    client_port: int | None
    server_ip: str
    server_port: int | None
    dns_id: int
    questions: list
    query_packet: int | None
    query_ts: float | None
    last_query_ts: float | None
    query_count: int = 0
    response_packet: int | None = None
    response_ts: float | None = None
    rcode: int | None = None
    truncated: bool = False
    answer_count: int | None = None
    status: str = "pending"  # answered | unanswered_* | unmatched_response
    note: str | None = None

    @property
    def qname(self) -> str | None:
        return self.questions[0][0] if self.questions else None

    @property
    def qtype(self) -> int | None:
        return self.questions[0][1] if self.questions else None

    @property
    def latency_ms(self) -> float | None:
        if self.status != "answered":
            return None
        return ms(self.response_ts - self.query_ts)

    @property
    def latency_from_last_query_ms(self) -> float | None:
        if self.status != "answered":
            return None
        return ms(self.response_ts - self.last_query_ts)


def _questions(meta: dict) -> list:
    out = []
    for q in (meta.get("questions") or [])[:MAX_QUESTIONS]:
        name = (q.get("name") or "").lower().rstrip(".")
        out.append((name, q.get("type")))
    return out


class DnsTracker:
    def __init__(self, config: DnsConfig | None = None) -> None:
        self.config = config or DnsConfig()
        self._pending: dict[tuple, Txn] = {}
        self._done: OrderedDict[tuple, Txn] = OrderedDict()
        self._txns: list[Txn] = []
        self.query_packets = 0
        self.response_packets = 0
        self.query_retransmission_packets = 0
        self.duplicate_responses = 0
        self.mismatched_responses = 0

    @property
    def transactions(self) -> list[Txn]:
        return self._txns

    def observe(self, v) -> None:
        meta = v.dns
        if meta is None or v.src_ip is None or v.dst_ip is None or meta.get("id") is None:
            return
        if v.is_retx:  # a TCP retransmission, not a DNS retry
            return
        transport = (v.transport or "").lower()
        if transport not in ("udp", "tcp"):
            return
        if meta.get("is_response"):
            self._response(v, meta, transport)
        else:
            self._query(v, meta, transport)

    # ------------------------------------------------------------------ queries
    def _query(self, v, meta: dict, transport: str) -> None:
        key = (v.src_ip, v.src_port, v.dst_ip, v.dst_port, meta["id"], transport)
        self.query_packets += 1
        pending = self._pending.get(key)
        if pending is not None:
            if v.ts - pending.last_query_ts <= self.config.retry_window_seconds:
                pending.query_count += 1
                pending.last_query_ts = v.ts
                self.query_retransmission_packets += 1
                return
            # Same id reused long after: the earlier query went unanswered for the whole
            # retry window, which is longer than the timeout, so it is an inferred timeout.
            pending.status = "unanswered_inferred_timeout"
            pending.note = "transaction id was reused after the retry window with no response"
            del self._pending[key]
        self._done.pop(key, None)  # a new query with this id starts a fresh transaction
        txn = Txn(
            id=len(self._txns) + 1, transport=transport,
            client_ip=v.src_ip, client_port=v.src_port, server_ip=v.dst_ip, server_port=v.dst_port,
            dns_id=meta["id"], questions=_questions(meta), query_packet=v.number,
            query_ts=v.ts, last_query_ts=v.ts, query_count=1,
        )
        self._txns.append(txn)
        self._pending[key] = txn

    # ---------------------------------------------------------------- responses
    def _response(self, v, meta: dict, transport: str) -> None:
        key = (v.dst_ip, v.dst_port, v.src_ip, v.src_port, meta["id"], transport)
        self.response_packets += 1
        pending = self._pending.get(key)
        if pending is not None:
            questions = _questions(meta)
            if questions and pending.questions and questions[0] != pending.questions[0]:
                self.mismatched_responses += 1
                self._unmatched(v, meta, transport, "question_mismatch")
                return
            wait = v.ts - pending.query_ts
            if wait < 0 or wait > self.config.match_window_seconds:
                self._unmatched(v, meta, transport, "outside_match_window")
                return
            pending.status = "answered"
            pending.response_packet, pending.response_ts = v.number, v.ts
            pending.rcode = meta.get("rcode")
            pending.truncated = bool(meta.get("tc"))
            pending.answer_count = meta.get("ancount")
            del self._pending[key]
            self._done[key] = pending
            if len(self._done) > _RECENT_DONE:
                self._done.popitem(last=False)
            return
        if key in self._done:
            self.duplicate_responses += 1
            return
        self._unmatched(v, meta, transport, "no_query_observed")

    def _unmatched(self, v, meta: dict, transport: str, note: str) -> None:
        self._txns.append(
            Txn(
                id=len(self._txns) + 1, transport=transport,
                client_ip=v.dst_ip, client_port=v.dst_port, server_ip=v.src_ip, server_port=v.src_port,
                dns_id=meta["id"], questions=_questions(meta), query_packet=None, query_ts=None,
                last_query_ts=None, query_count=0, response_packet=v.number, response_ts=v.ts,
                rcode=meta.get("rcode"), truncated=bool(meta.get("tc")),
                answer_count=meta.get("ancount"), status="unmatched_response", note=note,
            )
        )

    # ------------------------------------------------------------------ finalise
    def finalize(self, capture_end_ts: float | None) -> None:
        """Classify queries still pending when the capture ended."""
        for txn in self._pending.values():
            observed_for = (
                None if capture_end_ts is None else capture_end_ts - txn.last_query_ts
            )
            if observed_for is not None and observed_for >= self.config.timeout_seconds:
                txn.status = "unanswered_inferred_timeout"
                txn.note = f"no response within the {self.config.timeout_seconds:g}s the capture covered"
            else:
                txn.status = "unanswered_indeterminate"
                txn.note = "capture ended before a response could reasonably be expected"
        self._pending.clear()

    def rows(self) -> list[dict]:
        return [txn_row(t) for t in self._txns]

    def summary(self) -> dict:
        return summarize_dns(self)


def txn_row(t: Txn) -> dict:
    return {
        "transaction_id": t.id,
        "transport": t.transport,
        "client_ip": t.client_ip, "client_port": t.client_port,
        "server_ip": t.server_ip, "server_port": t.server_port,
        "dns_id": t.dns_id,
        "qname": t.qname, "qtype": qtype_name(t.qtype), "question_count": len(t.questions),
        "questions": [{"name": n, "type": qtype_name(q)} for n, q in t.questions],
        "query_packet": t.query_packet, "response_packet": t.response_packet,
        "query_ts": t.query_ts, "response_ts": t.response_ts,
        "query_count": t.query_count,
        "latency_ms": t.latency_ms,
        "latency_from_last_query_ms": t.latency_from_last_query_ms,
        "rcode": t.rcode, "rcode_name": rcode_name(t.rcode),
        "truncated": t.truncated, "answer_count": t.answer_count,
        "status": t.status, "note": t.note,
    }


def summarize_dns(tracker: DnsTracker) -> dict:
    txns = tracker.transactions
    answered = [t for t in txns if t.status == "answered"]
    unmatched = [t for t in txns if t.status == "unmatched_response"]
    timeout = [t for t in txns if t.status == "unanswered_inferred_timeout"]
    indeterminate = [t for t in txns if t.status == "unanswered_indeterminate"]
    pending_left = [t for t in txns if t.status == "pending"]  # finalize() not yet called

    queries = len(answered) + len(timeout) + len(indeterminate) + len(pending_left)
    responses = answered + unmatched  # duplicates are already excluded
    rcodes: dict[str, int] = {}
    for t in responses:
        name = rcode_name(t.rcode) or "UNKNOWN"
        rcodes[name] = rcodes.get(name, 0) + 1
    errors = sum(n for name, n in rcodes.items() if name != "NOERROR")
    server_failures = sum(n for name, n in rcodes.items() if name not in ("NOERROR", "NXDOMAIN"))

    latencies = [t.latency_ms for t in answered if t.latency_ms is not None]
    by_transport = {
        tr: distribution([t.latency_ms for t in answered if t.transport == tr and t.latency_ms is not None])
        for tr in ("udp", "tcp")
    }
    servers: dict[str, dict] = {}
    qtypes: dict[str, int] = {}
    for t in txns:
        if t.qtype is not None and t.status != "unmatched_response":
            name = qtype_name(t.qtype)
            qtypes[name] = qtypes.get(name, 0) + 1
        s = servers.setdefault(
            t.server_ip, {"server_ip": t.server_ip, "queries": 0, "answered": 0, "errors": 0, "_lat": []}
        )
        if t.status != "unmatched_response":
            s["queries"] += 1
        if t.status == "answered":
            s["answered"] += 1
            if t.latency_ms is not None:
                s["_lat"].append(t.latency_ms)
        if t.rcode not in (None, 0):
            s["errors"] += 1
    server_rows = []
    for s in servers.values():
        lat = s.pop("_lat")
        s["mean_latency_ms"] = sum(lat) / len(lat) if lat else None
        s["max_latency_ms"] = max(lat) if lat else None
        server_rows.append(s)
    server_rows.sort(key=lambda r: (-r["queries"], r["server_ip"]))

    return {
        "available": bool(txns),
        "transactions": len(txns),
        "queries": queries,
        "answered": len(answered),
        "unanswered": {
            "inferred_timeout": len(timeout),
            "indeterminate": len(indeterminate) + len(pending_left),
        },
        "unanswered_rate": ratio(len(timeout) + len(indeterminate) + len(pending_left), queries),
        "inferred_timeout_rate": ratio(len(timeout), queries),
        "unmatched_responses": len(unmatched),
        "query_packets": tracker.query_packets,
        "response_packets": tracker.response_packets,
        "query_retransmission_packets": tracker.query_retransmission_packets,
        "transactions_with_retransmitted_query": sum(1 for t in txns if t.query_count > 1),
        "duplicate_responses": tracker.duplicate_responses,
        "mismatched_responses": tracker.mismatched_responses,
        "responses_observed": len(responses),
        "rcodes": rcodes,
        "error_responses": errors,
        "error_response_rate": ratio(errors, len(responses)),
        "server_failures": server_failures,
        "server_failure_rate": ratio(server_failures, len(responses)),
        "nxdomain_rate": ratio(rcodes.get("NXDOMAIN", 0), len(responses)),
        "truncated_responses": sum(1 for t in responses if t.truncated),
        "latency_ms": distribution(latencies),
        "latency_by_transport_ms": by_transport,
        "qtypes": dict(sorted(qtypes.items(), key=lambda kv: (-kv[1], kv[0]))),
        "servers": server_rows[:20],
        "charts": {"latency_histogram": histogram(latencies, LATENCY_EDGES, "ms")},
    }
