"""Phase 4 network-intelligence metrics.

These modules are pure logic over :class:`PacketView` records (no Flask, SQLAlchemy or
Scapy imports) so every metric can be unit-tested with hand-built packets. The analysis
pipeline feeds them the same packets, flow ids and retransmission flags that the existing
FlowTracker / StatsAccumulator produce; they extend that pass rather than replace it.
"""
