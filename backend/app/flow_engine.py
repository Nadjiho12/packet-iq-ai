"""PacketIQ AI - flow engine (Week 2).

Turns parsed packet records (Week 1 `PacketRecord` objects or plain dicts with
the same keys) into stateful, *directional* 5-tuple flows.

Flow key : (src_ip, dst_ip, src_port, dst_port, protocol)
Per flow : first_seen, last_seen, packet_count, byte_count, destination port,
           TCP flag counters (SYN-only / SYN-ACK / ACK-after-SYN)
Per host : every destination port a source has contacted on a destination host

Robustness rules
  * Records are normalised first; missing or unexpected values become None
    (or 0 for length) instead of raising. A record without a valid src_ip,
    dst_ip and protocol cannot form a flow and is counted in `stats`, not
    dropped silently.
  * Ports may be None (ICMP, ICMPv6); the key then contains None.
  * A record without a usable timestamp still updates packet/byte counters
    but cannot move first_seen/last_seen.
"""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Set, Tuple

# Canonical order used by Scapy's str(TCP.flags); also the only letters accepted.
TCP_FLAG_ORDER = "FSRPAUEC"
_FLAG_BITS = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P",
              0x10: "A", 0x20: "U", 0x40: "E", 0x80: "C"}


class FlowKey(NamedTuple):
    """The required five fields. Directional: A->B and B->A are different flows."""

    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str


# ------------------------------------- #
# Normalisation helpers (never raise)   #
# ------------------------------------- #
def _get(rec: Any, name: str) -> Any:
    """Read a field from a dict-like or attribute-style record."""
    try:
        if isinstance(rec, Mapping):
            return rec.get(name)
        return getattr(rec, name, None)
    except Exception:
        return None


def _as_ip(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def _as_port(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, int) and 0 <= value <= 65535:
        return value
    return None


def _as_length(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, (int, float)) and math.isfinite(value) and value >= 0:
        return int(value)
    return 0


def _as_timestamp(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    return ts if math.isfinite(ts) and ts >= 0 else None


def _as_protocol(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _as_dns_query(value: Any) -> Optional[str]:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def parse_tcp_flags(value: Any) -> Optional[str]:
    """Canonical flag string ("S", "SA", "PA", ...), "" for no flags, None if unusable.

    None means "not a TCP packet / flags unknown". "" is a real TCP packet with
    no flag bits set (e.g. a NULL scan).
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        if not 0 <= value <= 0xFF:
            return None
        # bit order F,S,R,P,A,U,E,C matches TCP_FLAG_ORDER
        return "".join(_FLAG_BITS[b] for b in sorted(_FLAG_BITS) if value & b)
    if isinstance(value, str):
        letters = value.strip().upper()
        if all(ch in TCP_FLAG_ORDER for ch in letters):
            return "".join(ch for ch in TCP_FLAG_ORDER if ch in letters)
    return None


@dataclass
class NormalizedPacket:
    """Validated view of one record. Any field may be None except `length`."""

    timestamp: Optional[float]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    length: int
    tcp_flags: Optional[str]
    dns_query: Optional[str]

    @property
    def is_tcp(self) -> bool:
        return self.tcp_flags is not None

    @property
    def is_syn_only(self) -> bool:
        """TCP SYN without ACK = a new connection attempt."""
        return self.tcp_flags is not None and "S" in self.tcp_flags and "A" not in self.tcp_flags

    @property
    def is_synack(self) -> bool:
        return self.tcp_flags is not None and "S" in self.tcp_flags and "A" in self.tcp_flags

    @property
    def is_plain_ack(self) -> bool:
        """ACK set, no SYN/RST: handshake completion or established-state data."""
        return (self.tcp_flags is not None and "A" in self.tcp_flags
                and "S" not in self.tcp_flags and "R" not in self.tcp_flags)

    @property
    def flow_key(self) -> Optional[FlowKey]:
        if self.src_ip is None or self.dst_ip is None or self.protocol is None:
            return None
        return FlowKey(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


def normalize_packet(rec: Any) -> NormalizedPacket:
    """Build a NormalizedPacket from any record. Never raises."""
    return NormalizedPacket(
        timestamp=_as_timestamp(_get(rec, "timestamp")),
        src_ip=_as_ip(_get(rec, "src_ip")),
        dst_ip=_as_ip(_get(rec, "dst_ip")),
        src_port=_as_port(_get(rec, "src_port")),
        dst_port=_as_port(_get(rec, "dst_port")),
        protocol=_as_protocol(_get(rec, "protocol")),
        length=_as_length(_get(rec, "length")),
        tcp_flags=parse_tcp_flags(_get(rec, "tcp_flags")),
        dns_query=_as_dns_query(_get(rec, "dns_query")),
    )


def iso_utc(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


# ------------ #
# Flow state   #
# ------------ #
@dataclass
class Flow:
    """State of one directional 5-tuple flow."""

    key: FlowKey
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    packet_count: int = 0
    byte_count: int = 0
    flag_counts: Dict[str, int] = field(default_factory=dict)  # per flag letter
    syn_count: int = 0           # SYN without ACK (connection attempts)
    synack_count: int = 0        # SYN+ACK
    ack_after_syn: bool = False  # ACK (no SYN/RST) seen after a SYN: handshake completed
    saw_tcp: bool = False        # at least one packet carried TCP flags

    @property
    def dst_port(self) -> Optional[int]:
        return self.key.dst_port

    @property
    def duration(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def is_tcp(self) -> bool:
        return self.saw_tcp

    @property
    def established(self) -> bool:
        """True once this flow sent a SYN and later an ACK (3-way handshake completed).

        Prototype estimate: needs only this direction's packets. A SYN-ACK from the
        server is deliberately NOT enough, because a SYN flood also receives SYN-ACKs.
        """
        return self.syn_count > 0 and self.ack_after_syn

    @property
    def tcp_flags_seen(self) -> str:
        return "".join(ch for ch in TCP_FLAG_ORDER if ch in self.flag_counts)

    def update(self, pkt: NormalizedPacket) -> None:
        self.packet_count += 1
        self.byte_count += pkt.length
        ts = pkt.timestamp
        if ts is not None:
            self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
            self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)
        if pkt.tcp_flags is not None:
            self.saw_tcp = True
            for ch in pkt.tcp_flags:
                self.flag_counts[ch] = self.flag_counts.get(ch, 0) + 1
            if pkt.is_syn_only:
                self.syn_count += 1
            elif pkt.is_synack:
                self.synack_count += 1
            elif pkt.is_plain_ack and self.syn_count > 0:
                self.ack_after_syn = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.key.src_ip,
            "dst_ip": self.key.dst_ip,
            "src_port": self.key.src_port,
            "dst_port": self.key.dst_port,
            "protocol": self.key.protocol,
            "first_seen": self.first_seen,
            "first_seen_iso": iso_utc(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_iso": iso_utc(self.last_seen),
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "tcp_flags_seen": self.tcp_flags_seen,
            "syn_count": self.syn_count,
            "established": self.established,
        }


@dataclass
class FlowUpdate:
    """Result of FlowEngine.update(): the packet view and its flow (None if skipped)."""

    packet: NormalizedPacket
    flow: Optional[Flow]
    is_new: bool = False


class FlowEngine:
    """Aggregates packet records into directional 5-tuple flows."""

    def __init__(self) -> None:
        self.flows: Dict[FlowKey, Flow] = {}
        self.host_ports: Dict[Tuple[str, str], Set[int]] = {}
        self.stats: Dict[str, int] = {
            "records_seen": 0,
            "records_skipped_no_flow_key": 0,
            "records_without_timestamp": 0,
            "flows_created": 0,
        }

    def update(self, rec: Any) -> FlowUpdate:
        """Fold one record into its flow. Never raises."""
        self.stats["records_seen"] += 1
        pkt = normalize_packet(rec)
        if pkt.timestamp is None:
            self.stats["records_without_timestamp"] += 1
        key = pkt.flow_key
        if key is None:
            self.stats["records_skipped_no_flow_key"] += 1
            return FlowUpdate(packet=pkt, flow=None)
        flow = self.flows.get(key)
        is_new = flow is None
        if flow is None:
            flow = self.flows[key] = Flow(key=key)
            self.stats["flows_created"] += 1
        flow.update(pkt)
        if pkt.dst_port is not None:
            self.host_ports.setdefault((key.src_ip, key.dst_ip), set()).add(pkt.dst_port)
        return FlowUpdate(packet=pkt, flow=flow, is_new=is_new)

    def update_all(self, records: Iterable[Any]) -> None:
        for rec in records:
            self.update(rec)

    def get_flow(self, key: FlowKey) -> Optional[Flow]:
        return self.flows.get(key)

    def dst_ports_for(self, src_ip: str, dst_ip: str) -> Set[int]:
        """All destination ports `src_ip` has contacted on `dst_ip` (whole capture)."""
        return set(self.host_ports.get((src_ip, dst_ip), set()))

    def top_flows(self, n: int = 5, by: str = "byte_count") -> List[Flow]:
        return sorted(self.flows.values(), key=lambda f: getattr(f, by), reverse=True)[:n]
