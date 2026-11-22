"""Top talkers and inbound/outbound classification.

Definitions
- Only IP packets (IPv4 and IPv6) with both addresses are counted; ARP and other non-IP
  frames belong to no address. Bytes are on-the-wire frame sizes (original_length).
- ``total_ip_bytes`` / ``total_ip_packets`` are the denominators for every percentage here.
- Source ranking counts what an address *sent*; destination ranking what it *received*;
  bidirectional counts both (sent + received). A packet has two endpoints, so bidirectional
  percentages across addresses add up to about 200 %, not 100 %. A packet whose source and
  destination are the same address is counted on both sides for that address.

Direction (inbound / outbound / internal / unknown) is relative to the *configured* local
networks only. Private address ranges are NOT assumed to be local: a capture on a public
server has a public local address, and a capture inside one site may see several private
ranges that are not all "local". With the rule below:

    source local, destination local   -> internal
    source local, destination remote  -> outbound
    source remote, destination local  -> inbound
    neither endpoint local            -> unknown (transit, mirror or third-party traffic)

With no local networks configured every packet is ``unknown``. Multicast and broadcast
destinations are not special-cased: they are "remote" unless a configured network contains
them. IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are matched against IPv4 networks too.
"""

from __future__ import annotations

import heapq
import ipaddress
import re

from .common import ratio

MAX_LOCAL_NETWORKS = 64
DIRECTIONS = ("inbound", "outbound", "internal", "unknown")
TALKER_ROLES = ("source", "destination", "bidirectional")
TALKER_METRICS = ("bytes", "packets")
DIRECTION_EXPLANATION = {
    "inbound": "Source is outside the configured local networks and the destination is inside.",
    "outbound": "Source is inside the configured local networks and the destination is outside.",
    "internal": "Both source and destination are inside the configured local networks.",
    "unknown": "Neither endpoint is inside the configured local networks, or none are configured.",
}


class TrafficIntel:
    """Per-address and per-address-pair counters, one pass, memory ~ distinct addresses/pairs."""

    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self._ips: dict[str, list] = {}  # ip -> [sent_pkts, sent_bytes, recv_pkts, recv_bytes, ver]
        self._pairs: dict[tuple[str, str], list[int]] = {}
        self.version_totals = {4: [0, 0], 6: [0, 0]}

    def observe(self, v) -> None:
        if v.src_ip is None or v.dst_ip is None:
            return
        size = v.length
        self.total_packets += 1
        self.total_bytes += size
        if v.ip_version in self.version_totals:
            self.version_totals[v.ip_version][0] += 1
            self.version_totals[v.ip_version][1] += size
        src = self._ips.get(v.src_ip)
        if src is None:
            src = self._ips[v.src_ip] = [0, 0, 0, 0, v.ip_version]
        src[0] += 1
        src[1] += size
        dst = self._ips.get(v.dst_ip)
        if dst is None:
            dst = self._ips[v.dst_ip] = [0, 0, 0, 0, v.ip_version]
        dst[2] += 1
        dst[3] += size
        pair = self._pairs.get((v.src_ip, v.dst_ip))
        if pair is None:
            self._pairs[(v.src_ip, v.dst_ip)] = [1, size]
        else:
            pair[0] += 1
            pair[1] += size

    def ip_rows(self) -> list[dict]:
        return [
            {"ip": ip, "ip_version": r[4], "sent_packets": r[0], "sent_bytes": r[1],
             "received_packets": r[2], "received_bytes": r[3]}
            for ip, r in self._ips.items()
        ]

    def pair_rows(self) -> list[dict]:
        return [
            {"source_ip": s, "destination_ip": d, "packets": r[0], "bytes": r[1]}
            for (s, d), r in self._pairs.items()
        ]

    def summary(self, limit: int = 10) -> dict:
        rows = self.ip_rows()
        return {
            "total_ip_packets": self.total_packets,
            "total_ip_bytes": self.total_bytes,
            "unique_addresses": len(rows),
            "ip_versions": {
                f"ipv{ver}": {"packets": p, "bytes": b} for ver, (p, b) in self.version_totals.items()
            },
            "top_by_bytes": rank_talkers(rows, "bytes", "bidirectional", limit,
                                         self.total_packets, self.total_bytes),
        }


def _key(metric: str, role: str):
    if role == "bidirectional":
        if metric == "bytes":
            return lambda r: (r["sent_bytes"] + r["received_bytes"], r["ip"])
        return lambda r: (r["sent_packets"] + r["received_packets"], r["ip"])
    field = ("sent_" if role == "source" else "received_") + metric
    return lambda r: (r[field], r["ip"])


def rank_talkers(rows, metric: str, role: str, limit: int, total_packets: int, total_bytes: int,
                 ip_version: int | None = None) -> list[dict]:
    """Top ``limit`` addresses; ``rows`` may be any iterable (streamed, memory O(limit))."""
    if metric not in TALKER_METRICS or role not in TALKER_ROLES:
        raise ValueError("invalid metric or role")
    selected = (r for r in rows if ip_version is None or r["ip_version"] == ip_version)
    key = _key(metric, role)
    # Break ties by address so ordering is deterministic: larger value first, then ip ascending.
    top = heapq.nsmallest(limit, selected, key=lambda r: (-key(r)[0], r["ip"]))
    out = []
    for rank, r in enumerate(top, start=1):
        sent_p, sent_b = r["sent_packets"], r["sent_bytes"]
        recv_p, recv_b = r["received_packets"], r["received_bytes"]
        if role == "source":
            pk, by = sent_p, sent_b
        elif role == "destination":
            pk, by = recv_p, recv_b
        else:
            pk, by = sent_p + recv_p, sent_b + recv_b
        pct_b, pct_p = ratio(by, total_bytes), ratio(pk, total_packets)
        out.append(
            {
                "rank": rank,
                "ip": r["ip"],
                "ip_version": r["ip_version"],
                "packets": pk,
                "bytes": by,
                "sent_packets": sent_p, "sent_bytes": sent_b,
                "received_packets": recv_p, "received_bytes": recv_b,
                "percent_of_bytes": None if pct_b is None else 100 * pct_b,
                "percent_of_packets": None if pct_p is None else 100 * pct_p,
            }
        )
    return out


# ----------------------------------------------------------------------- direction


def parse_local_networks(spec) -> list:
    """Parse "10.0.0.0/8, 192.168.1.5 2001:db8::/32" (or a list) into ip_network objects.

    A bare address becomes a /32 or /128. Raises ValueError with a client-safe message.
    """
    if spec is None:
        return []
    tokens = re.split(r"[,\s;]+", spec.strip()) if isinstance(spec, str) else list(spec)
    tokens = [t.strip() for t in tokens if t and t.strip()]
    if len(tokens) > MAX_LOCAL_NETWORKS:
        raise ValueError(f"At most {MAX_LOCAL_NETWORKS} local networks may be configured.")
    networks = []
    for token in tokens:
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            raise ValueError(f"{token[:64]!r} is not a valid IPv4/IPv6 address or CIDR network.") from None
    return networks


class _Locality:
    def __init__(self, networks) -> None:
        self.networks = networks
        self._cache: dict[str, bool] = {}

    def is_local(self, ip: str) -> bool:
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            self._cache[ip] = False
            return False
        candidates = [addr]
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            candidates.append(mapped)
        result = any(a in net for a in candidates for net in self.networks)
        self._cache[ip] = result
        return result


def classify_direction(src: str, dst: str, locality: _Locality) -> str:
    if not locality.networks:
        return "unknown"
    s, d = locality.is_local(src), locality.is_local(dst)
    if s and d:
        return "internal"
    if s:
        return "outbound"
    if d:
        return "inbound"
    return "unknown"


def direction_stats(pairs, networks, total_packets: int, total_bytes: int) -> dict:
    """Aggregate directional pair rows ({source_ip, destination_ip, packets, bytes})."""
    locality = _Locality(networks)
    totals = {d: [0, 0] for d in DIRECTIONS}
    for r in pairs:
        d = classify_direction(r["source_ip"], r["destination_ip"], locality)
        totals[d][0] += r["packets"]
        totals[d][1] += r["bytes"]
    return {
        "configured": bool(networks),
        "local_networks": [str(n) for n in networks],
        "unknown_reason": None if networks else "no_local_networks_configured",
        "total_ip_packets": total_packets,
        "total_ip_bytes": total_bytes,
        "directions": {
            d: {
                "packets": p,
                "bytes": b,
                "percent_of_packets": None if not total_packets else 100 * p / total_packets,
                "percent_of_bytes": None if not total_bytes else 100 * b / total_bytes,
                "explanation": DIRECTION_EXPLANATION[d],
            }
            for d, (p, b) in totals.items()
        },
        "rule": "internal = both endpoints local; outbound = only source local; "
                "inbound = only destination local; unknown = neither local or none configured.",
    }
