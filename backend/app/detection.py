"""PacketIQ AI - detection engine (Week 2): the five handbook heuristic rules.

    RULE-001  Port Scan                 >20 unique destination ports on one host in 10 s
    RULE-002  Unusual Traffic Volume    >10 MB in one flow
    RULE-003  High-Frequency Connects   >100 connection attempts to one destination in 5 s
    RULE-004  Suspicious DNS            query length >50 characters, or suspicious pattern
    RULE-005  TCP SYN Flood Pattern     SYN ratio >80% without established ACK state

Every comparison is strict (">"): a value exactly equal to a threshold does NOT
alert. Thresholds live in `Thresholds` (defaults = handbook values).

Time model
  * Rules use packet timestamps, never the wall clock, so results are repeatable.
  * Windows are inclusive: an event is in a window of W seconds while
    (now - event_time) <= W.
  * Timestamps that go backwards are clamped to the newest timestamp seen
    (`run_detection()` sorts records first so this does not occur on PCAPs).
  * A record without a usable timestamp updates flow counters and may raise the
    timestamp-free rules (RULE-002, RULE-004) but is ignored by the windowed
    rules (RULE-001, -003, -005).

Alerts are de-duplicated: the same (rule, key) alerts at most once per
`alert_cooldown_s` seconds of packet time (RULE-002: once per flow).
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import sys
from collections import Counter, deque
from dataclasses import asdict, dataclass
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple

from backend.app.flow_engine import (
    FlowEngine,
    FlowKey,
    FlowUpdate,
    NormalizedPacket,
    _as_timestamp,
    _get,
    iso_utc,
)

log = logging.getLogger(__name__)

SEVERITIES = ("low", "medium", "high", "critical")


# ------------------------------- #
# Rule catalogue and thresholds
# ------------------------------- #
@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    name: str
    severity: str
    description: str


# One fixed severity per rule keeps rule_id <-> severity consistent everywhere.
RULES: Dict[str, RuleInfo] = {
    "RULE-001": RuleInfo("RULE-001", "Port Scan", "medium",
                         ">20 unique destination ports on one host within 10 seconds"),
    "RULE-002": RuleInfo("RULE-002", "Unusual Traffic Volume", "medium",
                         ">10 MB transferred in a single flow"),
    "RULE-003": RuleInfo("RULE-003", "High-Frequency Connects", "high",
                         ">100 connection attempts to one destination within 5 seconds"),
    "RULE-004": RuleInfo("RULE-004", "Suspicious DNS", "medium",
                         "DNS query longer than 50 characters or matching a suspicious pattern"),
    "RULE-005": RuleInfo("RULE-005", "TCP SYN Flood Pattern", "high",
                         "SYN ratio above 80% without established ACK state"),
}


@dataclass(frozen=True)
class Thresholds:
    # --- values given in the assignment / handbook ---
    port_scan_unique_ports: int = 20
    port_scan_window_s: float = 10.0
    volume_bytes: int = 10 * 1024 * 1024        # "10 MB" read as 10 MiB (see report)
    connect_attempts: int = 100
    connect_window_s: float = 5.0
    dns_max_length: int = 50
    syn_ratio: float = 0.8
    # --- prototype parameters NOT given in the handbook (documented in the report) ---
    syn_window_s: float = 10.0                  # window over which the SYN ratio is measured
    syn_min_packets: int = 50                   # minimum half-open SYNs before RULE-005 may fire
    dns_entropy_min_label_len: int = 16
    dns_entropy_bits: float = 3.5
    dns_hex_label_len: int = 32
    dns_digit_min_label_len: int = 12
    dns_digit_ratio: float = 0.6
    alert_cooldown_s: float = 60.0


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    timestamp: Optional[float]
    timestamp_iso: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    summary: str
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------- #
# Helpers   #
# --------- #

def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character (0.0 for empty input)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def dns_suspicion(query: str, th: Thresholds) -> Tuple[List[str], Dict[str, Any]]:
    """Return (reasons, details) for a DNS query name; empty reasons = not suspicious."""
    name = query.strip().rstrip(".").lower()
    labels = [lab for lab in name.split(".") if lab]
    reasons: List[str] = []
    details: Dict[str, Any] = {"query_length": len(name)}

    if len(name) > th.dns_max_length:
        reasons.append(f"query_length>{th.dns_max_length}")

    for lab in labels:
        has_digit = any(ch.isdigit() for ch in lab)
        has_alpha = any(ch.isalpha() for ch in lab)
        if (len(lab) >= th.dns_entropy_min_label_len and has_digit and has_alpha
                and shannon_entropy(lab) >= th.dns_entropy_bits):
            reasons.append("high_entropy_label")
            details["entropy_label"] = lab
            details["entropy_bits"] = round(shannon_entropy(lab), 2)
            break
    for lab in labels:
        if len(lab) >= th.dns_hex_label_len and all(ch in "0123456789abcdef" for ch in lab):
            reasons.append("hex_encoded_label")
            details["hex_label_length"] = len(lab)
            break
    for lab in labels:
        if (len(lab) >= th.dns_digit_min_label_len
                and sum(ch.isdigit() for ch in lab) / len(lab) >= th.dns_digit_ratio):
            reasons.append("digit_heavy_label")
            break
    return reasons, details


class _PortWindow:
    """Sliding window of (time, dst_port) with an O(1) unique-port count."""

    def __init__(self) -> None:
        self.events: Deque[Tuple[float, int]] = deque()
        self.counts: Dict[int, int] = {}

    def add(self, t: float, port: int) -> None:
        self.events.append((t, port))
        self.counts[port] = self.counts.get(port, 0) + 1

    def prune(self, t: float, window: float) -> None:
        while self.events and t - self.events[0][0] > window:
            _, port = self.events.popleft()
            self.counts[port] -= 1
            if self.counts[port] == 0:
                del self.counts[port]

    @property
    def unique(self) -> int:
        return len(self.counts)

    @property
    def oldest(self) -> Optional[float]:
        return self.events[0][0] if self.events else None


class _TcpWindow:
    """Sliding window of TCP packets destined to one host, for RULE-005."""

    def __init__(self) -> None:
        self.events: Deque[Tuple[float, FlowKey, bool]] = deque()  # (t, flow key, is SYN-only)
        self.syn = 0

    def add(self, t: float, key: FlowKey, is_syn: bool) -> None:
        self.events.append((t, key, is_syn))
        self.syn += is_syn

    def prune(self, t: float, window: float) -> None:
        while self.events and t - self.events[0][0] > window:
            _, _, is_syn = self.events.popleft()
            self.syn -= is_syn

    @property
    def total(self) -> int:
        return len(self.events)


_MISSING = object()


# --------- #
# Engine
# --------- #
class DetectionEngine:
    """Feeds packet records through the flow engine, then through the five rules."""

    def __init__(self, thresholds: Optional[Thresholds] = None,
                 flow_engine: Optional[FlowEngine] = None) -> None:
        self.th = thresholds or Thresholds()
        self.flows = flow_engine or FlowEngine()
        self.alerts: List[Alert] = []
        self.stats: Dict[str, int] = {
            "packets_processed": 0,
            "packets_without_timestamp": 0,
            "internal_errors": 0,
        }
        self._clock: Optional[float] = None
        self._ports: Dict[Tuple[str, str], _PortWindow] = {}
        self._attempts: Dict[Tuple[str, str], Deque[float]] = {}
        self._tcp: Dict[str, _TcpWindow] = {}
        self._last_alert: Dict[Tuple[str, Any], Optional[float]] = {}

    # API
    def process(self, rec: Any) -> List[Alert]:
        """Process one packet record; return the alerts it newly raised. Never raises."""
        self.stats["packets_processed"] += 1
        new: List[Alert] = []
        try:
            upd = self.flows.update(rec)
            pkt = upd.packet
            t = self._advance_clock(pkt.timestamp)
            if t is None:
                self.stats["packets_without_timestamp"] += 1
            if upd.flow is not None:
                new += self._rule_volume(upd)
                if t is not None:
                    new += self._rule_port_scan(pkt, t)
                    new += self._rule_connects(upd, t)
                    new += self._rule_syn_flood(pkt, t)
            new += self._rule_dns(pkt)
        except Exception:  # a bug must not kill the whole analysis run
            self.stats["internal_errors"] += 1
            log.exception("detection failed on one record")
        self.alerts.extend(new)
        return new

    def process_all(self, records: Iterable[Any]) -> List[Alert]:
        out: List[Alert] = []
        for rec in records:
            out += self.process(rec)
        return out

    # internals
    def _advance_clock(self, ts: Optional[float]) -> Optional[float]:
        if ts is None:
            return None
        self._clock = ts if self._clock is None else max(ts, self._clock)
        return self._clock

    def _suppressed(self, rule_id: str, key: Any, ts: Optional[float],
                    cooldown: Optional[float]) -> bool:
        prev = self._last_alert.get((rule_id, key), _MISSING)
        if prev is _MISSING:
            return False
        if cooldown is None or ts is None or prev is None:
            return True
        return (ts - prev) < cooldown

    def _alert(self, rule_id: str, key: Any, ts: Optional[float], cooldown: Optional[float],
               src_ip: Optional[str], dst_ip: Optional[str], summary: str,
               evidence: Dict[str, Any]) -> List[Alert]:
        if self._suppressed(rule_id, key, ts, cooldown):
            return []
        self._last_alert[(rule_id, key)] = ts
        info = RULES[rule_id]
        return [Alert(rule_id=rule_id, rule_name=info.name, severity=info.severity,
                      timestamp=ts, timestamp_iso=iso_utc(ts), src_ip=src_ip,
                      dst_ip=dst_ip, summary=summary, evidence=evidence)]

    # RULE-001
    def _rule_port_scan(self, pkt: NormalizedPacket, t: float) -> List[Alert]:
        if pkt.dst_port is None:
            return []
        key = (pkt.src_ip, pkt.dst_ip)
        win = self._ports.setdefault(key, _PortWindow())
        win.add(t, pkt.dst_port)
        win.prune(t, self.th.port_scan_window_s)
        if win.unique <= self.th.port_scan_unique_ports:
            return []
        evidence = {
            "unique_dst_ports": win.unique,
            "threshold": self.th.port_scan_unique_ports,
            "window_seconds": self.th.port_scan_window_s,
            "window_start": win.oldest,
            "window_end": t,
            "ports_sample": sorted(win.counts)[:25],
        }
        return self._alert(
            "RULE-001", key, t, self.th.alert_cooldown_s, pkt.src_ip, pkt.dst_ip,
            f"{pkt.src_ip} contacted {win.unique} unique ports on {pkt.dst_ip} "
            f"within {self.th.port_scan_window_s:g}s", evidence)

    # RULE-002
    def _rule_volume(self, upd: FlowUpdate) -> List[Alert]:
        flow = upd.flow
        if flow is None or flow.byte_count <= self.th.volume_bytes:
            return []
        evidence = {
            "byte_count": flow.byte_count,
            "threshold_bytes": self.th.volume_bytes,
            "packet_count": flow.packet_count,
            "duration_seconds": round(flow.duration, 6),
            "flow": {"src_ip": flow.key.src_ip, "dst_ip": flow.key.dst_ip,
                     "src_port": flow.key.src_port, "dst_port": flow.key.dst_port,
                     "protocol": flow.key.protocol},
            "first_seen": flow.first_seen,
            "last_seen": flow.last_seen,
        }
        ts = upd.packet.timestamp
        return self._alert(
            "RULE-002", flow.key, ts, None, flow.key.src_ip, flow.key.dst_ip,
            f"flow {flow.key.src_ip}:{flow.key.src_port} -> {flow.key.dst_ip}:{flow.key.dst_port} "
            f"carried {flow.byte_count} bytes (> {self.th.volume_bytes})", evidence)

    # RULE-003
    @staticmethod
    def _is_attempt(upd: FlowUpdate) -> bool:
        """Connection attempt estimate: TCP SYN without ACK, or first packet of a non-TCP flow."""
        pkt = upd.packet
        return pkt.is_syn_only if pkt.is_tcp else upd.is_new

    def _rule_connects(self, upd: FlowUpdate, t: float) -> List[Alert]:
        pkt = upd.packet
        if not self._is_attempt(upd):
            return []
        key = (pkt.src_ip, pkt.dst_ip)
        q = self._attempts.setdefault(key, deque())
        q.append(t)
        while q and t - q[0] > self.th.connect_window_s:
            q.popleft()
        if len(q) <= self.th.connect_attempts:
            return []
        evidence = {
            "connection_attempts": len(q),
            "threshold": self.th.connect_attempts,
            "window_seconds": self.th.connect_window_s,
            "window_start": q[0],
            "window_end": t,
            "attempt_definition": "TCP SYN without ACK; first packet of a non-TCP flow",
        }
        return self._alert(
            "RULE-003", key, t, self.th.alert_cooldown_s, pkt.src_ip, pkt.dst_ip,
            f"{pkt.src_ip} made {len(q)} connection attempts to {pkt.dst_ip} "
            f"within {self.th.connect_window_s:g}s", evidence)

    # RULE-004
    def _rule_dns(self, pkt: NormalizedPacket) -> List[Alert]:
        query = pkt.dns_query
        if not query:
            return []
        if pkt.src_port == 53 and pkt.dst_port != 53:
            return []  # a response repeats the question; judge the query, not the answer
        reasons, details = dns_suspicion(query, self.th)
        if not reasons:
            return []
        evidence = {"query": query, "reasons": reasons,
                    "length_threshold": self.th.dns_max_length, **details}
        return self._alert(
            "RULE-004", (pkt.src_ip, query.lower()), pkt.timestamp, None,
            pkt.src_ip, pkt.dst_ip,
            f"suspicious DNS query ({', '.join(reasons)}): {query[:80]}", evidence)

    # RULE-005
    def _rule_syn_flood(self, pkt: NormalizedPacket, t: float) -> List[Alert]:
        if not pkt.is_tcp or pkt.dst_ip is None:
            return []
        key = pkt.flow_key
        if key is None:
            return []
        win = self._tcp.setdefault(pkt.dst_ip, _TcpWindow())
        win.add(t, key, pkt.is_syn_only)
        win.prune(t, self.th.syn_window_s)
        th = self.th
        # Cheap upper bound first: raw SYN-only share ignores later handshakes.
        if win.syn < th.syn_min_packets or win.syn / win.total <= th.syn_ratio:
            return []
        if self._suppressed("RULE-005", pkt.dst_ip, t, th.alert_cooldown_s):
            return []
        half_open = 0
        half_open_flows: Set[FlowKey] = set()
        established_flows: Set[FlowKey] = set()
        for _, k, is_syn in win.events:
            if not is_syn:
                continue
            flow = self.flows.get_flow(k)
            if flow is not None and flow.established:
                established_flows.add(k)
            else:
                half_open += 1
                half_open_flows.add(k)
        ratio = half_open / win.total
        if half_open < th.syn_min_packets or ratio <= th.syn_ratio:
            return []
        evidence = {
            "syn_without_ack_packets": half_open,
            "total_tcp_packets": win.total,
            "syn_ratio": round(ratio, 4),
            "threshold_ratio": th.syn_ratio,
            "min_syn_packets": th.syn_min_packets,
            "half_open_flows": len(half_open_flows),
            "established_flows": len(established_flows),
            "window_seconds": th.syn_window_s,
            "window_start": win.events[0][0],
            "window_end": t,
        }
        return self._alert(
            "RULE-005", pkt.dst_ip, t, th.alert_cooldown_s, None, pkt.dst_ip,
            f"{half_open}/{win.total} TCP packets to {pkt.dst_ip} are SYNs with no "
            f"completed handshake ({ratio:.0%})", evidence)


# ---------------------- #
# Convenience pipeline
# ---------------------- #
def sort_records(records: Iterable[Any]) -> List[Any]:
    """Stable sort by timestamp; records without a usable timestamp go last."""
    def key(rec: Any) -> Tuple[bool, float]:
        ts = _as_timestamp(_get(rec, "timestamp"))
        return (ts is None, ts if ts is not None else 0.0)
    return sorted(records, key=key)


def run_detection(records: Iterable[Any], thresholds: Optional[Thresholds] = None,
                  sort: bool = True) -> DetectionEngine:
    """Run all records through flow aggregation and the five rules."""
    engine = DetectionEngine(thresholds)
    engine.process_all(sort_records(records) if sort else records)
    return engine


# -------------------------------------------------------- #
# CLI:  python -m backend.app.detection <pcap> [--json]
# -------------------------------------------------------- #
def _print_report(engine: DetectionEngine) -> None:
    fs = engine.flows.stats
    print(f"packets processed : {engine.stats['packets_processed']}")
    print(f"flows             : {len(engine.flows.flows)} "
          f"(skipped, no flow key: {fs['records_skipped_no_flow_key']})")
    print("\nTop flows by bytes")
    for f in engine.flows.top_flows(5):
        k = f.key
        print(f"  {k.src_ip}:{k.src_port} -> {k.dst_ip}:{k.dst_port} {k.protocol:<6} "
              f"pkts={f.packet_count:<5} bytes={f.byte_count:<9} "
              f"dur={f.duration:.2f}s flags={f.tcp_flags_seen or '-'}")
    print(f"\nAlerts ({len(engine.alerts)})")
    for a in engine.alerts:
        print(f"  [{a.severity.upper():<6}] {a.rule_id} {a.rule_name:<24} "
              f"t={a.timestamp_iso}  {a.summary}")


def main(argv: Optional[List[str]] = None) -> int:
    from backend.app.capture import PcapReadError, read_pcap  # local import: keeps module light

    ap = argparse.ArgumentParser(prog="detection", description="PacketIQ AI detection engine")
    ap.add_argument("pcap")
    ap.add_argument("--json", action="store_true", help="print alerts as JSON")
    args = ap.parse_args(argv)
    try:
        records = read_pcap(args.pcap)
    except PcapReadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    engine = run_detection(records)
    if args.json:
        print(json.dumps([a.to_dict() for a in engine.alerts], indent=2))
    else:
        _print_report(engine)
    return 0


if __name__ == "__main__":
    sys.exit(main())
