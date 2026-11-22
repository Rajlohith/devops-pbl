"""Unit tests for the Phase 4 analytics modules, using hand-built PacketViews."""

import unittest

from tests.analytics_helpers import T0, Trace

from app.services.analytics.anomalies import (
    AnomalyInputs, AnomalyThresholds, ProtocolPortObserver, detect,
)
from app.services.analytics.common import distribution, histogram, percentile, ratio, seq_diff
from app.services.analytics.dns_analytics import DnsConfig, DnsTracker
from app.services.analytics.engine import AdvancedAnalyzer
from app.services.analytics.tcp_connections import TcpConnectionTracker
from app.services.analytics.tcp_diagnostics import indicator_rows, window_summary
from app.services.analytics.traffic_intel import (
    TrafficIntel, classify_direction, direction_stats, parse_local_networks, rank_talkers,
    _Locality,
)

C, S = "10.0.0.1", "10.0.0.2"


def tcp_tracker(trace):
    tracker = TcpConnectionTracker()
    for v in trace.views:
        tracker.observe(v)
    return tracker


class HelperTests(unittest.TestCase):
    def test_ratio_none_on_zero_denominator(self):
        self.assertIsNone(ratio(0, 0))
        self.assertEqual(ratio(1, 4), 0.25)

    def test_percentile_matches_linear_interpolation(self):
        self.assertAlmostEqual(percentile([1, 2, 3, 4], 0.5), 2.5)
        self.assertAlmostEqual(percentile([10.0], 0.95), 10.0)
        d = distribution([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertEqual((d["count"], d["min"], d["max"], d["median"]), (5, 1.0, 5.0, 3.0))
        self.assertIsNone(distribution([]))

    def test_seq_diff_handles_wraparound(self):
        self.assertEqual(seq_diff(5, 0xFFFFFFFB), 10)
        self.assertEqual(seq_diff(0xFFFFFFFB, 5), -10)

    def test_histogram_buckets(self):
        rows = histogram([0.5, 3, 20, 100], [0, 1, 10], "s")
        self.assertEqual([r["count"] for r in rows], [1, 1, 2])


class TcpConnectionTests(unittest.TestCase):
    def test_complete_handshake_is_established_with_timings(self):
        t = Trace()
        t.handshake(0.0, rtt=0.05)
        tr = tcp_tracker(t)
        (c,) = tr.connections
        self.assertEqual(c.state, "established")
        times = c.times()
        self.assertAlmostEqual(times["syn_to_synack_ms"], 50.0, places=3)
        self.assertAlmostEqual(times["handshake_ms"], 60.0, places=3)
        self.assertAlmostEqual(times["synack_to_ack_ms"], 10.0, places=3)
        s = tr.summary()
        self.assertEqual(s["success_rate"], 1.0)
        self.assertEqual(s["observable_attempts"], 1)

    def test_unanswered_syn_is_incomplete_not_failed(self):
        t = Trace()
        t.tcp(0, C, 40000, S, 80, "S", seq=100)
        tr = tcp_tracker(t)
        (c,) = tr.connections
        self.assertEqual((c.state, c.incomplete_reason), ("incomplete", "no_synack"))
        s = tr.summary()
        self.assertEqual(s["success_rate"], 0.0)
        self.assertEqual(s["confirmed_failure_rate"], 0.0)  # nothing is *confirmed* failed
        self.assertEqual(s["incomplete_rate"], 1.0)

    def test_syn_synack_without_ack_is_incomplete_no_final_ack(self):
        t = Trace()
        t.tcp(0, C, 40000, S, 80, "S", seq=100)
        t.tcp(0.05, S, 80, C, 40000, "SA", seq=500, ack=101)
        (c,) = tcp_tracker(t).connections
        self.assertEqual((c.state, c.incomplete_reason), ("incomplete", "no_final_ack"))
        self.assertIsNone(c.times()["handshake_ms"])

    def test_rst_ack_to_syn_is_confirmed_refused(self):
        t = Trace()
        t.tcp(0, C, 40000, S, 80, "S", seq=100)
        t.tcp(0.01, S, 80, C, 40000, "RA", seq=0, ack=101)
        tr = tcp_tracker(t)
        self.assertEqual(tr.connections[0].state, "refused")
        s = tr.summary()
        self.assertEqual(s["confirmed_failure_rate"], 1.0)
        self.assertEqual(s["resets"]["reset_before_established"], 1)

    def test_mid_stream_connection_is_unclassified_and_excluded(self):
        t = Trace()
        t.tcp(0, C, 40000, S, 80, "PA", seq=101, ack=501, payload=10)
        t.tcp(0.1, S, 80, C, 40000, "A", seq=501, ack=111)
        tr = tcp_tracker(t)
        (c,) = tr.connections
        self.assertEqual(c.state, "unclassified")
        self.assertIn("start_not_observed", c.truncation_reasons)
        s = tr.summary()
        self.assertIsNone(s["success_rate"])  # no observable attempts: unavailable, not 0
        self.assertEqual(s["observable_attempts"], 0)

    def test_success_rate_denominator_mixes_states(self):
        t = Trace()
        t.handshake(0, cport=40000)                                  # established
        t.tcp(1, C, 40001, S, 80, "S", seq=1)                        # incomplete
        t.tcp(2, C, 40002, S, 80, "S", seq=1)                        # refused
        t.tcp(2.01, S, 80, C, 40002, "RA", ack=2)
        t.tcp(3, C, 40003, S, 80, "PA", seq=9, ack=9, payload=5)     # unclassified
        s = tcp_tracker(t).summary()
        self.assertEqual(s["states"], {"established": 1, "incomplete": 1, "refused": 1, "unclassified": 1})
        self.assertEqual(s["observable_attempts"], 3)
        self.assertAlmostEqual(s["success_rate"], 1 / 3)

    def test_syn_retransmission_is_not_a_new_connection(self):
        t = Trace()
        t.tcp(0, C, 40000, S, 80, "S", seq=100)
        t.tcp(1, C, 40000, S, 80, "S", seq=100)
        t.tcp(1.05, S, 80, C, 40000, "SA", seq=500, ack=101)
        t.tcp(1.06, C, 40000, S, 80, "A", seq=101, ack=501)
        tr = tcp_tracker(t)
        self.assertEqual(len(tr.connections), 1)
        c = tr.connections[0]
        self.assertEqual(c.syn_count, 2)
        self.assertAlmostEqual(c.times()["handshake_ms"], 1060.0, places=3)  # from the first SYN

    def test_port_reuse_creates_second_connection(self):
        t = Trace()
        t.handshake(0, isn_c=100, isn_s=500)
        t.tcp(0.2, C, 40000, S, 80, "FA", seq=101, ack=501)
        t.tcp(0.21, S, 80, C, 40000, "FA", seq=501, ack=102)
        t.handshake(5, isn_c=9000, isn_s=7000)
        tr = tcp_tracker(t)
        self.assertEqual([c.state for c in tr.connections], ["established", "established"])
        self.assertEqual(tr.connections[0].termination, "fin")
        self.assertEqual(tr.connections[1].termination, "none")
        self.assertIn("end_not_observed", tr.connections[1].truncation_reasons)

    def test_termination_kinds(self):
        t = Trace()
        t.handshake(0, cport=1)
        t.tcp(1, C, 1, S, 80, "FA", seq=101, ack=501)                # half closed
        t.handshake(2, cport=2)
        t.tcp(3, S, 80, C, 2, "R", seq=501)                          # reset by server (b)
        t.handshake(4, cport=3)
        t.tcp(5, C, 3, S, 80, "FA", seq=101, ack=501)
        t.tcp(5.1, S, 80, C, 3, "FA", seq=501, ack=102)
        t.tcp(5.2, C, 3, S, 80, "R", seq=102)                        # RST after graceful close
        c1, c2, c3 = tcp_tracker(t).connections
        self.assertEqual((c1.termination, c1.terminated_by), ("half_closed", "a"))
        self.assertEqual((c2.termination, c2.terminated_by), ("reset", "b"))
        self.assertEqual(c3.termination, "fin")
        self.assertEqual(c3.rst_total, 1)  # the RST still counts toward reset statistics

    def test_reset_rates_and_denominators(self):
        t = Trace()
        t.handshake(0, cport=1)
        t.tcp(1, S, 80, C, 1, "R", seq=501)
        t.tcp(1.1, S, 80, C, 1, "R", seq=501)       # two RST packets, one connection
        t.handshake(2, cport=2)
        tr = tcp_tracker(t)
        r = tr.summary()["resets"]
        self.assertEqual(r["rst_packets"], 2)
        self.assertEqual(r["connections_with_reset"], 1)
        self.assertEqual(r["tcp_connections"], 2)
        self.assertAlmostEqual(r["packet_rate"], 2 / 8)
        self.assertAlmostEqual(r["connection_rate"], 0.5)
        self.assertEqual(r["reset_after_established"], 1)
        self.assertEqual(r["top_senders"][0], {"ip": S, "rst_packets": 2})

    def test_ipv6_connection(self):
        t = Trace()
        t.handshake(0, client="2001:db8::1", server="2001:db8::2", ipv=6)
        (c,) = tcp_tracker(t).connections
        self.assertEqual((c.state, c.ip_version), ("established", 6))

    def test_non_tcp_and_non_ip_ignored(self):
        t = Trace()
        t.udp(0, C, 5000, S, 53)
        self.assertEqual(tcp_tracker(t).connections, [])


class TcpDiagnosticsTests(unittest.TestCase):
    def _est(self):
        t = Trace()
        t.handshake(0)
        return t

    def _ind(self, trace):
        (c,) = tcp_tracker(trace).connections
        return c, {(r["type"], r["side"]): r for r in indicator_rows(c)}

    def test_retransmission_counted_once_not_as_gap_or_overlap(self):
        t = self._est()
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(0.5, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)  # exact duplicate
        c, ind = self._ind(t)
        self.assertEqual(ind[("retransmission", "a")]["count"], 1)
        self.assertNotIn(("partial_overlap", "a"), ind)
        self.assertNotIn(("sequence_gap", "a"), ind)

    def test_triple_duplicate_ack_run(self):
        t = self._est()
        t.tcp(0.10, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(0.11, C, 40000, S, 80, "PA", seq=201, ack=501, payload=100)   # in flight
        t.tcp(0.20, S, 80, C, 40000, "A", seq=501, ack=201)                 # baseline ack
        for i in range(3):
            t.tcp(0.3 + i * 0.01, S, 80, C, 40000, "A", seq=501, ack=201)   # dup acks
        _, ind = self._ind(t)
        dup = ind[("duplicate_ack", "b")]
        self.assertEqual(dup["count"], 3)
        self.assertEqual(dup["detail"]["max_run"], 3)
        self.assertEqual(dup["severity"], "medium")
        self.assertTrue(dup["evidence"])

    def test_repeated_ack_without_outstanding_data_is_not_duplicate(self):
        t = self._est()
        for i in range(4):
            t.tcp(0.2 + i * 0.1, S, 80, C, 40000, "A", seq=501, ack=101)
        _, ind = self._ind(t)
        self.assertNotIn(("duplicate_ack", "b"), ind)

    def test_data_segment_between_acks_resets_duplicate_run(self):
        t = self._est()
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=50)
        t.tcp(0.2, S, 80, C, 40000, "A", seq=501, ack=151)
        t.tcp(0.3, S, 80, C, 40000, "PA", seq=501, ack=151, payload=10)
        t.tcp(0.4, S, 80, C, 40000, "A", seq=511, ack=151)
        _, ind = self._ind(t)
        self.assertNotIn(("duplicate_ack", "b"), ind)

    def test_sequence_gap_then_fill_is_out_of_order(self):
        t = self._est()
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(0.2, C, 40000, S, 80, "PA", seq=301, ack=501, payload=100)   # skips 201..300
        t.tcp(0.3, C, 40000, S, 80, "PA", seq=201, ack=501, payload=100)   # late arrival fills it
        c, ind = self._ind(t)
        gap = ind[("sequence_gap", "a")]
        self.assertEqual(gap["count"], 1)
        self.assertEqual(gap["detail"]["unfilled_gaps"], 0)
        self.assertEqual(ind[("out_of_order", "a")]["count"], 1)

    def test_unfilled_gap_reports_potentially_missing_range(self):
        t = self._est()
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(0.2, C, 40000, S, 80, "PA", seq=401, ack=501, payload=100)   # 201..400 never seen
        _, ind = self._ind(t)
        gap = ind[("sequence_gap", "a")]
        self.assertEqual(gap["detail"]["unfilled_gap_bytes"], 200)
        self.assertEqual(gap["evidence"][0]["start"], 201)
        self.assertEqual(gap["confidence"], "low")  # nothing corroborates it

    def test_gap_confidence_rises_with_duplicate_acks(self):
        t = self._est()
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(0.2, C, 40000, S, 80, "PA", seq=301, ack=501, payload=100)
        t.tcp(0.3, S, 80, C, 40000, "A", seq=501, ack=201)
        t.tcp(0.31, S, 80, C, 40000, "A", seq=501, ack=201)
        _, ind = self._ind(t)
        self.assertEqual(ind[("sequence_gap", "a")]["confidence"], "medium")
        self.assertEqual(ind[("sequence_gap", "a")]["severity"], "medium")

    def test_sequence_wraparound_is_in_order(self):
        t = Trace()
        t.handshake(0, isn_c=0xFFFFFF00 - 1, isn_s=500)
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=0xFFFFFF00, ack=501, payload=0x100)
        t.tcp(0.2, C, 40000, S, 80, "PA", seq=0, ack=501, payload=100)  # wrapped, contiguous
        _, ind = self._ind(t)
        self.assertNotIn(("sequence_gap", "a"), ind)
        self.assertNotIn(("partial_overlap", "a"), ind)

    def test_keepalive_probe_is_ignored(self):
        t = self._est()
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(5.0, C, 40000, S, 80, "A", seq=200, ack=501, payload=1)  # one byte behind
        _, ind = self._ind(t)
        self.assertNotIn(("partial_overlap", "a"), ind)

    def test_resegmented_retransmission_is_partial_overlap(self):
        t = self._est()
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(0.5, C, 40000, S, 80, "PA", seq=101, ack=501, payload=150)  # different length
        _, ind = self._ind(t)
        self.assertEqual(ind[("partial_overlap", "a")]["count"], 1)

    def test_capture_starting_midstream_cannot_judge_before_first_segment(self):
        t = Trace()
        t.tcp(0, C, 40000, S, 80, "PA", seq=100000, ack=1, payload=100)
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=100100, ack=1, payload=100)
        _, ind = self._ind(t)
        self.assertEqual(ind, {})

    def test_window_scaling_negotiated(self):
        t = Trace()
        t.handshake(0, wsc_c=7, wsc_s=8)
        t.tcp(0.1, C, 40000, S, 80, "A", seq=101, ack=501, window=100)
        t.tcp(0.2, S, 80, C, 40000, "A", seq=501, ack=101, window=200)
        (c,) = tcp_tracker(t).connections
        w = window_summary(c)
        self.assertEqual(w["scaling"], "negotiated")
        self.assertEqual(w["a"]["scale_shift"], 7)
        self.assertEqual(w["a"]["effective"]["last"], 100 << 7)
        self.assertEqual(w["b"]["effective"]["max"], 200 << 8)

    def test_window_scaling_not_negotiated_when_one_side_omits_option(self):
        t = Trace()
        t.handshake(0, wsc_c=7, wsc_s=None)
        t.tcp(0.1, C, 40000, S, 80, "A", seq=101, ack=501, window=100)
        (c,) = tcp_tracker(t).connections
        w = window_summary(c)
        self.assertEqual(w["scaling"], "not_negotiated")
        self.assertEqual(w["a"]["effective"]["last"], 100)  # shift 0

    def test_window_scale_unknown_without_handshake_gives_null_effective(self):
        t = Trace()
        t.tcp(0, C, 40000, S, 80, "A", seq=101, ack=501, window=100)
        t.tcp(0.1, S, 80, C, 40000, "A", seq=501, ack=101, window=0)
        (c,) = tcp_tracker(t).connections
        w = window_summary(c)
        self.assertEqual(w["scaling"], "unknown_handshake_not_observed")
        self.assertIsNone(w["a"]["effective"])
        self.assertEqual(w["a"]["raw"]["last"], 100)
        self.assertEqual(w["b"]["zero_window_events"], 1)

    def test_zero_window_episodes_and_changes(self):
        t = Trace()
        t.handshake(0)
        for i, win in enumerate([500, 0, 0, 0, 300, 0]):
            t.tcp(0.1 + i * 0.1, S, 80, C, 40000, "A", seq=501, ack=101, window=win)
        (c,) = tcp_tracker(t).connections
        w = window_summary(c)["b"]
        self.assertEqual(w["zero_window_events"], 2)    # two separate episodes
        self.assertEqual(w["zero_window_packets"], 4)
        self.assertEqual(w["changes"], 3)
        self.assertEqual(len(w["zero_window_evidence"]), 2)

    def test_scale_option_capped_at_14(self):
        t = Trace()
        t.handshake(0, wsc_c=20, wsc_s=3)
        t.tcp(0.1, C, 40000, S, 80, "A", seq=101, ack=501, window=1)
        (c,) = tcp_tracker(t).connections
        self.assertEqual(window_summary(c)["a"]["scale_shift"], 14)


class DnsTests(unittest.TestCase):
    def run_dns(self, build, config=None, end=None):
        t = Trace()
        build(t)
        tracker = DnsTracker(config)
        for v in t.views:
            tracker.observe(v)
        tracker.finalize(end if end is not None else max(v.ts for v in t.views))
        return tracker

    def test_matched_latency_and_ids(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7)
            t.dns_response(0.042, C, 5000, "8.8.8.8", 7)
        tracker = self.run_dns(build)
        (txn,) = tracker.transactions
        self.assertEqual(txn.status, "answered")
        self.assertAlmostEqual(txn.latency_ms, 42.0, places=3)
        s = tracker.summary()
        self.assertEqual(s["answered"], 1)
        self.assertAlmostEqual(s["latency_ms"]["mean"], 42.0, places=3)
        self.assertEqual(s["error_response_rate"], 0.0)

    def test_different_id_or_port_does_not_match(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7)
            t.dns_response(0.01, C, 5000, "8.8.8.8", 8)       # wrong id
            t.dns_response(0.02, C, 5001, "8.8.8.8", 7)       # wrong client port
        tracker = self.run_dns(build, end=T0 + 100)
        s = tracker.summary()
        self.assertEqual(s["unmatched_responses"], 2)
        self.assertEqual(s["unanswered"]["inferred_timeout"], 1)

    def test_query_retransmission_not_double_counted_latency_from_first(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7)
            t.dns_query(1.0, C, 5000, "8.8.8.8", 7)           # client retry, same id
            t.dns_response(1.2, C, 5000, "8.8.8.8", 7)
        tracker = self.run_dns(build)
        (txn,) = tracker.transactions
        self.assertEqual(txn.query_count, 2)
        self.assertAlmostEqual(txn.latency_ms, 1200.0, places=3)
        self.assertAlmostEqual(txn.latency_from_last_query_ms, 200.0, places=3)
        s = tracker.summary()
        self.assertEqual(s["queries"], 1)
        self.assertEqual(s["query_retransmission_packets"], 1)

    def test_duplicate_response_ignored(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7)
            t.dns_response(0.05, C, 5000, "8.8.8.8", 7)
            t.dns_response(0.06, C, 5000, "8.8.8.8", 7)
        s = self.run_dns(build).summary()
        self.assertEqual((s["answered"], s["unmatched_responses"], s["duplicate_responses"]), (1, 0, 1))
        self.assertEqual(s["responses_observed"], 1)

    def test_response_without_query_is_unmatched(self):
        def build(t):
            t.dns_response(0.0, C, 5000, "8.8.8.8", 9, rcode=3)
        tracker = self.run_dns(build)
        s = tracker.summary()
        self.assertEqual(s["unmatched_responses"], 1)
        self.assertEqual(s["queries"], 0)
        self.assertEqual(s["rcodes"], {"NXDOMAIN": 1})  # still counted as an observed response
        self.assertIsNone(s["latency_ms"])

    def test_rcode_breakdown_and_failure_rates(self):
        codes = [0, 0, 3, 2, 5, 1]

        def build(t):
            for i, rc in enumerate(codes):
                t.dns_query(i, C, 6000 + i, "8.8.8.8", i + 1)
                t.dns_response(i + 0.01, C, 6000 + i, "8.8.8.8", i + 1, rcode=rc)
        s = self.run_dns(build).summary()
        self.assertEqual(s["rcodes"], {"NOERROR": 2, "NXDOMAIN": 1, "SERVFAIL": 1, "REFUSED": 1, "FORMERR": 1})
        self.assertAlmostEqual(s["error_response_rate"], 4 / 6)
        self.assertAlmostEqual(s["server_failure_rate"], 3 / 6)   # NXDOMAIN excluded
        self.assertAlmostEqual(s["nxdomain_rate"], 1 / 6)

    def test_unanswered_timeout_inferred_only_when_capture_long_enough(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 1)
            t.dns_query(58.0, C, 5001, "8.8.8.8", 2)           # asked 2s before the capture ends
            t.udp(60.0, C, 1, "10.9.9.9", 9)                   # padding packet ends the capture
        s = self.run_dns(build, end=T0_END).summary()
        self.assertEqual(s["unanswered"], {"inferred_timeout": 1, "indeterminate": 1})
        self.assertAlmostEqual(s["inferred_timeout_rate"], 0.5)

    def test_failure_rate_ignores_unanswered_queries(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 1)
            t.dns_response(0.01, C, 5000, "8.8.8.8", 1, rcode=2)
            t.dns_query(1.0, C, 5001, "8.8.8.8", 2)            # never answered
        s = self.run_dns(build, end=T0_END).summary()
        self.assertEqual(s["error_response_rate"], 1.0)         # 1 error / 1 response, not / 2 queries

    def test_udp_and_tcp_are_separate_transactions(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7)
            t.dns_response(0.01, C, 5000, "8.8.8.8", 7, tc=True)
            t.tcp(0.1, C, 5000, "8.8.8.8", 53, "S", seq=1)      # TCP retry on the same ports
            t.dns_query(0.12, C, 5000, "8.8.8.8", 7, transport="TCP")
            t.dns_response(0.2, C, 5000, "8.8.8.8", 7, transport="TCP")
        tracker = self.run_dns(build)
        s = tracker.summary()
        self.assertEqual(s["answered"], 2)
        self.assertEqual(s["truncated_responses"], 1)
        self.assertEqual(s["latency_by_transport_ms"]["tcp"]["count"], 1)
        self.assertEqual(s["latency_by_transport_ms"]["udp"]["count"], 1)

    def test_tcp_retransmitted_dns_segment_is_not_a_dns_retry(self):
        def build(t):
            q = t.dns_query(0.0, C, 5000, "8.8.8.8", 7, transport="TCP")
            r = t.dns_query(0.5, C, 5000, "8.8.8.8", 7, transport="TCP")
            r.is_retx = True
        tracker = self.run_dns(build, end=T0_END)
        self.assertEqual(tracker.query_retransmission_packets, 0)
        self.assertEqual(tracker.summary()["queries"], 1)

    def test_question_mismatch_is_unmatched(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7, name="a.test")
            t.dns_response(0.1, C, 5000, "8.8.8.8", 7, name="b.test")
        s = self.run_dns(build, end=T0_END).summary()
        self.assertEqual((s["answered"], s["unmatched_responses"], s["mismatched_responses"]), (0, 1, 1))

    def test_response_without_question_section_matches_by_id(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7)
            t.dns_response(0.1, C, 5000, "8.8.8.8", 7, rcode=1, questions=False)
        self.assertEqual(self.run_dns(build).summary()["answered"], 1)

    def test_multiple_questions_single_transaction(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7, extra=[{"name": "two.test", "type": 28}])
            t.dns_response(0.1, C, 5000, "8.8.8.8", 7)
        tracker = self.run_dns(build)
        (txn,) = tracker.transactions
        self.assertEqual(len(txn.questions), 2)
        self.assertEqual(tracker.summary()["queries"], 1)

    def test_id_reuse_after_retry_window_starts_new_transaction(self):
        def build(t):
            t.dns_query(0.0, C, 5000, "8.8.8.8", 7)
            t.dns_query(100.0, C, 5000, "8.8.8.8", 7)
            t.dns_response(100.1, C, 5000, "8.8.8.8", 7)
        tracker = self.run_dns(build)
        self.assertEqual([t.status for t in tracker.transactions],
                         ["unanswered_inferred_timeout", "answered"])

    def test_no_dns_means_unavailable(self):
        s = DnsTracker().summary()
        self.assertFalse(s["available"])
        self.assertIsNone(s["error_response_rate"])
        self.assertIsNone(s["latency_ms"])


T0_END = T0 + 60.0


class TrafficTests(unittest.TestCase):
    def _traffic(self):
        t = Trace()
        t.udp(0, "10.0.0.1", 1, "8.8.8.8", 53, payload=100)           # 142 bytes
        t.udp(1, "8.8.8.8", 53, "10.0.0.1", 1, payload=400)           # 442
        t.udp(2, "10.0.0.1", 1, "10.0.0.2", 2, payload=58)            # 100
        t.udp(3, "2001:db8::1", 1, "2001:db8::2", 2, payload=8, ipv=6)  # 50
        ti = TrafficIntel()
        for v in t.views:
            ti.observe(v)
        return ti

    def test_ranking_percentages_and_ipv6(self):
        ti = self._traffic()
        self.assertEqual(ti.total_bytes, 142 + 442 + 100 + 50)
        rows = ti.ip_rows()
        top = rank_talkers(rows, "bytes", "source", 2, ti.total_packets, ti.total_bytes)
        self.assertEqual([r["ip"] for r in top], ["8.8.8.8", "10.0.0.1"])
        self.assertEqual(top[0]["bytes"], 442)
        self.assertAlmostEqual(top[0]["percent_of_bytes"], 100 * 442 / ti.total_bytes)
        v6 = rank_talkers(rows, "packets", "bidirectional", 10, ti.total_packets, ti.total_bytes, ip_version=6)
        self.assertEqual({r["ip"] for r in v6}, {"2001:db8::1", "2001:db8::2"})
        limited = rank_talkers(rows, "bytes", "destination", 1, ti.total_packets, ti.total_bytes)
        self.assertEqual(len(limited), 1)

    def test_bidirectional_counts_both_directions(self):
        ti = self._traffic()
        top = rank_talkers(ti.ip_rows(), "bytes", "bidirectional", 1, ti.total_packets, ti.total_bytes)
        self.assertEqual(top[0]["ip"], "10.0.0.1")
        self.assertEqual(top[0]["bytes"], 142 + 442 + 100)

    def test_non_ip_and_invalid_args(self):
        ti = TrafficIntel()
        t = Trace()
        v = t.udp(0, "1.1.1.1", 1, "2.2.2.2", 2)
        v.src_ip = None  # e.g. ARP carries no IP addresses
        ti.observe(v)
        self.assertEqual(ti.total_packets, 0)
        with self.assertRaises(ValueError):
            rank_talkers([], "frames", "source", 1, 0, 0)

    def test_direction_unknown_when_nothing_configured(self):
        ti = self._traffic()
        stats = direction_stats(ti.pair_rows(), [], ti.total_packets, ti.total_bytes)
        self.assertFalse(stats["configured"])
        self.assertEqual(stats["directions"]["unknown"]["packets"], ti.total_packets)
        self.assertEqual(stats["unknown_reason"], "no_local_networks_configured")

    def test_direction_classification_with_cidr_and_ipv6(self):
        ti = self._traffic()
        nets = parse_local_networks("10.0.0.0/24, 2001:db8::/32")
        d = direction_stats(ti.pair_rows(), nets, ti.total_packets, ti.total_bytes)["directions"]
        self.assertEqual((d["outbound"]["bytes"], d["inbound"]["bytes"]), (142, 442))
        self.assertEqual(d["internal"]["bytes"], 100 + 50)
        self.assertEqual(d["unknown"]["packets"], 0)

    def test_private_addresses_are_not_assumed_local(self):
        loc = _Locality(parse_local_networks("192.168.1.0/24"))
        self.assertEqual(classify_direction("10.0.0.1", "10.0.0.2", loc), "unknown")
        self.assertEqual(classify_direction("192.168.1.9", "10.0.0.2", loc), "outbound")
        self.assertEqual(classify_direction("10.0.0.2", "192.168.1.9", loc), "inbound")

    def test_single_host_and_mapped_addresses(self):
        nets = parse_local_networks(["203.0.113.5", "2001:db8::7"])
        self.assertEqual([str(n) for n in nets], ["203.0.113.5/32", "2001:db8::7/128"])
        loc = _Locality(nets)
        self.assertEqual(classify_direction("::ffff:203.0.113.5", "1.1.1.1", loc), "outbound")

    def test_parse_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            parse_local_networks("10.0.0.0/8, not-an-ip")
        with self.assertRaises(ValueError):
            parse_local_networks("10.0.0.0/33")
        with self.assertRaises(ValueError):
            parse_local_networks(",".join(f"10.0.{i}.0/24" for i in range(65)))
        self.assertEqual(parse_local_networks(""), [])


class AnomalyTests(unittest.TestCase):
    def run_rules(self, build, thresholds=None, dns_end=None, ts=None, transport_rows=None):
        t = Trace()
        build(t)
        az = AdvancedAnalyzer(thresholds)
        for v in t.views:
            az.observe_view(v)
        last = max(v.ts for v in t.views)
        return az.finalize(
            last_ts=dns_end or last, total_packets=len(t.views),
            transport_rows=transport_rows or [], timeseries=ts or {"points": []},
        )

    @staticmethod
    def rules(result):
        return {f["rule"]: f for f in result.findings}

    def test_port_scan_vertical_has_full_explanation(self):
        def build(t):
            for i in range(25):
                t.tcp(i * 0.1, "10.0.0.9", 50000 + i, S, 1000 + i, "S", seq=1)
        r = self.run_rules(build)
        f = self.rules(r)["port_scan_vertical"]
        self.assertEqual(f["severity"], "medium")
        self.assertIn("25 distinct TCP ports", f["reason"])
        self.assertEqual(f["thresholds"], {"port_scan_distinct_ports": 20})
        self.assertEqual(f["affected_ips"], sorted(["10.0.0.9", S]))
        self.assertTrue(f["packet_refs"] and f["affected_flows"])
        self.assertIn("not prove", f["note"])
        self.assertTrue(all(k in f for k in ("rule", "name", "severity", "description", "evidence", "reason")))

    def test_below_threshold_produces_no_scan_finding(self):
        def build(t):
            for i in range(19):
                t.tcp(i, "10.0.0.9", 50000 + i, S, 1000 + i, "S", seq=1)
        self.assertNotIn("port_scan_vertical", self.rules(self.run_rules(build)))

    def test_horizontal_scan(self):
        def build(t):
            for i in range(21):
                t.tcp(i, "10.0.0.9", 50000 + i, f"10.1.0.{i + 1}", 22, "S", seq=1)
        f = self.rules(self.run_rules(build))["port_scan_horizontal"]
        self.assertEqual(f["evidence"]["distinct_hosts"], 21)

    def test_high_connection_rate_uses_sliding_window(self):
        def build(t):
            for i in range(120):
                t.tcp(i * 0.05, "10.0.0.9", 40000 + i, S, 80, "S", seq=1)   # 120 within 6 s
        f = self.rules(self.run_rules(build))["high_connection_rate"]
        self.assertEqual(f["evidence"]["connections_in_window"], 120)

    def test_spread_out_connections_do_not_trigger_rate_rule(self):
        def build(t):
            for i in range(120):
                t.tcp(i * 1.0, "10.0.0.9", 40000 + i, S, 80, "S", seq=1)
        self.assertNotIn("high_connection_rate", self.rules(self.run_rules(build)))

    def test_repeated_attempts_requires_mostly_unsuccessful(self):
        def build(t):
            for i in range(6):
                t.tcp(i, "10.0.0.9", 40000 + i, S, 443, "S", seq=1)
        f = self.rules(self.run_rules(build))["repeated_connection_attempts"]
        self.assertEqual(f["evidence"]["not_completed"], 6)

        def healthy(t):
            for i in range(6):
                t.handshake(i * 2, client="10.0.0.9", cport=40000 + i, sport=443)
        self.assertNotIn("repeated_connection_attempts", self.rules(self.run_rules(healthy)))

    def test_reset_rules(self):
        def build(t):
            t.handshake(0)
            for i in range(30):
                t.tcp(1 + i * 0.01, S, 80, C, 40000, "R", seq=501 + i)
        rules = self.rules(self.run_rules(build))
        self.assertIn("high_reset_rate", rules)
        self.assertNotIn("reset_source_host", rules)   # 30 < 50
        th = AnomalyThresholds.from_overrides({"reset_host_threshold": 10})
        self.assertIn("reset_source_host", self.rules(self.run_rules(build, th)))

    def test_dns_nxdomain_long_names_and_subdomains(self):
        def build(t):
            for i in range(30):
                t.dns_query(i, C, 7000 + i, "8.8.8.8", i + 1, name=f"{'x' * 45}{i}.evil.test")
                t.dns_response(i + 0.01, C, 7000 + i, "8.8.8.8", i + 1, name=f"{'x' * 45}{i}.evil.test", rcode=3)
            for i in range(55):
                t.dns_query(40 + i, C, 8000 + i, "8.8.8.8", 100 + i, name=f"s{i}.tunnel.example")
        rules = self.rules(self.run_rules(build))
        self.assertEqual(rules["dns_nxdomain_burst"]["evidence"]["nxdomain"], 30)
        self.assertIn("dns_long_names", rules)
        self.assertEqual(rules["dns_many_subdomains"]["evidence"]["domain"], "tunnel.example")

    def test_protocol_port_rules(self):
        def build(t):
            for i in range(6):
                v = t.udp(i, C, 4000 + i, S, 53, payload=30)       # port 53, but not DNS
            for i in range(3):
                t.udp(10 + i, C, 4100 + i, S, 22, payload=10)      # UDP to SSH port
            v = t.tcp(20, C, 40200, S, 9999, "PA", seq=1, payload=40)
            v.app = "HTTP"
        rules = self.rules(self.run_rules(build))
        self.assertEqual(rules["non_dns_on_dns_port"]["evidence"]["packets"], 6)
        self.assertIn("udp_on_tcp_service_port", rules)
        self.assertEqual(rules["http_on_nonstandard_port"]["evidence"]["port"], 9999)

    def test_dns_on_53_and_http_on_80_are_not_flagged(self):
        def build(t):
            t.dns_query(0, C, 5000, "8.8.8.8", 1)
            v = t.tcp(1, C, 4200, S, 80, "PA", seq=1, payload=40)
            v.app = "HTTP"
        rules = self.rules(self.run_rules(build))
        self.assertNotIn("non_dns_on_dns_port", rules)
        self.assertNotIn("http_on_nonstandard_port", rules)

    def test_volume_burst_concentration_icmp(self):
        def build(t):
            for i in range(6):
                t.udp(i, f"10.0.1.{i}", 1, "10.0.2.1", 2, payload=10)
            t.udp(7, "10.0.9.9", 1, "10.0.2.1", 2, payload=1_000_000)
        th = AnomalyThresholds.from_overrides({"high_volume_host_bytes": 500_000})
        points = [{"time": f"t{i}", "packets_per_second": 10.0 if i != 5 else 900.0} for i in range(12)]
        rows = [{"protocol": "ICMP", "packets": 200}]
        r = self.run_rules(build, th, ts={"bucket_seconds": 1, "points": points}, transport_rows=rows)
        rules = self.rules(r)
        self.assertEqual(rules["high_volume_host"]["affected_ips"], ["10.0.9.9"])
        self.assertAlmostEqual(rules["traffic_burst"]["evidence"]["ratio"], 90.0)
        self.assertIn("host_traffic_concentration", rules)
        self.assertEqual(rules["icmp_heavy"]["evidence"]["icmp_packets"], 200)

    def test_findings_sorted_by_severity_and_numbered(self):
        def build(t):
            for i in range(25):
                t.tcp(i * 0.1, "10.0.0.9", 50000 + i, S, 1000 + i, "S", seq=1)
            for i in range(6):
                t.udp(i, C, 4000 + i, S, 22, payload=10)
        findings = self.run_rules(build).findings
        order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        sev = [order[f["severity"]] for f in findings]
        self.assertEqual(sev, sorted(sev, reverse=True))
        self.assertEqual([f["finding_id"] for f in findings], list(range(1, len(findings) + 1)))

    def test_threshold_overrides_validated(self):
        th = AnomalyThresholds.from_overrides({"port_scan_distinct_ports": 5})
        self.assertEqual(th.port_scan_distinct_ports, 5)
        for bad in ({"nope": 1}, {"port_scan_distinct_ports": 0}, {"port_scan_distinct_ports": "x"},
                    {"port_scan_distinct_ports": True}):
            with self.assertRaises(ValueError):
                AnomalyThresholds.from_overrides(bad)

    def test_benign_capture_has_no_findings(self):
        def build(t):
            t.handshake(0)
            t.dns_query(1, C, 5000, "8.8.8.8", 1)
            t.dns_response(1.02, C, 5000, "8.8.8.8", 1)
        self.assertEqual(self.run_rules(build).findings, [])


class EngineTests(unittest.TestCase):
    def test_empty_capture_yields_unavailable_not_zero(self):
        r = AdvancedAnalyzer().finalize(last_ts=None, total_packets=0, transport_rows=[],
                                        timeseries={"points": []})
        d = r.document
        self.assertIsNone(d["tcp"]["success_rate"])
        self.assertIsNone(d["resets"]["packet_rate"])
        self.assertIsNone(d["dns"]["error_response_rate"])
        self.assertIsNone(d["diagnostics"]["retransmission_rate"])
        self.assertIsNone(d["tcp"]["handshake_ms"])
        self.assertEqual((r.connections, r.dns_transactions, r.findings), ([], [], []))
        self.assertEqual(d["traffic"]["top_by_bytes"], [])

    def test_document_shape_and_no_fabricated_loss_figure(self):
        t = Trace()
        t.handshake(0)
        az = AdvancedAnalyzer()
        for v in t.views:
            az.observe_view(v)
        r = az.finalize(last_ts=T0 + 1, total_packets=3, transport_rows=[], timeseries={"points": []})
        d = r.document
        for key in ("tcp", "resets", "diagnostics", "windows", "dns", "traffic", "anomalies",
                    "thresholds", "definitions", "limitations"):
            self.assertIn(key, d)
        self.assertIsNone(d["diagnostics"]["packet_loss_percent"])
        self.assertEqual(d["diagnostics"]["packet_loss_status"], "not_measurable_from_a_single_capture")
        self.assertFalse(d["dns"]["available"])
        self.assertEqual(len(r.connections), 1)
        self.assertEqual(r.connections[0]["state"], "established")
        self.assertEqual(d["windows"]["scaling_status"], {"not_negotiated": 1})

    def test_retransmission_counted_once_across_modules(self):
        t = Trace()
        t.handshake(0)
        t.tcp(0.1, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        t.tcp(0.6, C, 40000, S, 80, "PA", seq=101, ack=501, payload=100)
        az = AdvancedAnalyzer()
        for v in t.views:
            az.observe_view(v)
        r = az.finalize(last_ts=T0 + 1, total_packets=5, transport_rows=[], timeseries={"points": []})
        self.assertEqual(r.document["diagnostics"]["retransmission_packets"], 1)
        self.assertEqual(r.connections[0]["retransmissions"], 1)


if __name__ == "__main__":
    unittest.main()
