"""PacketIQ AI - capture module (Week 1).

Responsibilities
  1. Interface discovery            -> list_interfaces()
  2. Offline PCAP reading           -> iter_pcap() / read_pcap()
  3. Packet parsing to flat records -> parse_packet()
  4. Guarded, short live capture    -> capture_live()   (authorized lab traffic only)

Design rules
  * parse_packet() NEVER raises. Anything it cannot extract is None, and every
    record has exactly the same keys, so downstream code (DB, API, AI) needs no
    per-protocol special cases.
  * Protocol label = most specific recognised layer, in this priority order:
        DNS > TCP > UDP > ICMP > ICMPv6 > ARP > OTHER
  * Non-IP frames (ARP, raw Ethernet) keep src_ip/dst_ip = None.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    IPv6,
    Packet,
    PcapReader,
    conf,
    get_if_list,
    sniff,
)
from scapy.error import Scapy_Exception

log = logging.getLogger(__name__)

# Hard limits for live capture: the assignment requires a *short* documented test.

MAX_LIVE_PACKETS = 1000
MAX_LIVE_SECONDS = 60


class PcapReadError(Exception):
    """The file is missing, not a PCAP/PCAPNG, or corrupt."""


class CaptureError(Exception):
    """Live capture could not be started (privileges, bad interface, ...)."""


@dataclass
class PacketRecord:
    """Flat, protocol-independent view of one packet. Absent fields are None."""

    index: int
    timestamp: Optional[float]          # epoch seconds
    timestamp_iso: Optional[str]        # UTC ISO-8601
    length: int                         # bytes on the wire (falls back to captured length)
    src_ip: Optional[str]
    dst_ip: Optional[str]
    ip_version: Optional[int]           # 4, 6 or None
    protocol: str                       # DNS|TCP|UDP|ICMP|ICMPv6|ARP|OTHER
    src_port: Optional[int]
    dst_port: Optional[int]
    tcp_flags: Optional[str]            # e.g. "S", "SA", "PA"; TCP only
    dns_query: Optional[str]            # first question name, no trailing dot
    parse_error: Optional[str] = None   # set only if dissection failed

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


#######################
# Interface discovery #
#######################

def list_interfaces() -> List[Dict[str, Optional[str]]]:
    """Return available capture interfaces as dicts: name, description, ip, mac."""
    interfaces: List[Dict[str, Optional[str]]] = []
    try:
        for iface in conf.ifaces.values():
            interfaces.append(
                {
                    "name": str(iface.name),
                    "description": str(getattr(iface, "description", "") or "") or None,
                    "ip": str(getattr(iface, "ip", "") or "") or None,
                    "mac": str(getattr(iface, "mac", "") or "") or None,
                }
            )
    except Exception as exc:  # defensive: conf.ifaces differs across platforms
        log.warning("conf.ifaces failed (%s); falling back to get_if_list()", exc)
        interfaces = [
            {"name": n, "description": None, "ip": None, "mac": None}
            for n in get_if_list()
        ]
    return interfaces


##################
# Packet parsing #
##################

def _dns_query_name(pkt: Packet) -> Optional[str]:
    """First DNS question name, decoded, without trailing dot (None if no question)."""
    qr = pkt.getlayer(DNSQR)
    if qr is None:
        return None
    name = qr.qname
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")
    return str(name).rstrip(".") or None


def _has_icmpv6(pkt: Packet) -> bool:
    # ICMPv6 has dozens of classes in scapy; match on the shared name prefix.
    return any(layer.__name__.startswith("ICMPv6") for layer in pkt.layers())


def parse_packet(pkt: Packet, index: int = 0) -> PacketRecord:
    """Convert a scapy packet into a PacketRecord. Never raises."""
    try:
        ts_raw = getattr(pkt, "time", None)
        ts = float(ts_raw) if ts_raw is not None else None
        ts_iso = (
            datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            if ts is not None
            else None
        )
        length = getattr(pkt, "wirelen", None) or len(pkt)

        # ---- network layer ----
        src_ip = dst_ip = None
        ip_version = None
        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip, dst_ip, ip_version = ip.src, ip.dst, 4
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            src_ip, dst_ip, ip_version = ip6.src, ip6.dst, 6

        # ---- transport layer ----
        src_port = dst_port = None
        tcp_flags = None
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port, dst_port, tcp_flags = int(tcp.sport), int(tcp.dport), str(tcp.flags)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port, dst_port = int(udp.sport), int(udp.dport)

        # ---- application layer + protocol label -----
        dns_query = None
        if pkt.haslayer(DNS):
            dns_query = _dns_query_name(pkt)
            protocol = "DNS"
        elif pkt.haslayer(TCP):
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        elif _has_icmpv6(pkt):
            protocol = "ICMPv6"
        elif pkt.haslayer(ARP):
            protocol = "ARP"
        else:
            protocol = "OTHER"

        return PacketRecord(
            index=index,
            timestamp=ts,
            timestamp_iso=ts_iso,
            length=int(length),
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=ip_version,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            dns_query=dns_query,
        )
    except Exception as exc:  # malformed packet: keep the slot, flag the error
        log.warning("packet %d could not be parsed: %s", index, exc)
        return PacketRecord(
            index=index, timestamp=None, timestamp_iso=None, length=0,
            src_ip=None, dst_ip=None, ip_version=None, protocol="OTHER",
            src_port=None, dst_port=None, tcp_flags=None, dns_query=None,
            parse_error=f"{type(exc).__name__}: {exc}",
        )


########################
# Offline PCAP reading #
########################

def iter_pcap(path: Union[str, Path]) -> Iterator[PacketRecord]:
    """Stream PacketRecords from a PCAP/PCAPNG file (memory-friendly)."""
    p = Path(path)
    if not p.is_file():
        raise PcapReadError(f"PCAP file not found: {p}")
    try:
        with PcapReader(str(p)) as reader:
            for i, pkt in enumerate(reader):
                yield parse_packet(pkt, index=i)
    except (Scapy_Exception, OSError, EOFError) as exc:
        raise PcapReadError(f"Cannot read {p}: {exc}") from exc


def read_pcap(path: Union[str, Path], limit: Optional[int] = None) -> List[PacketRecord]:
    """Parse a PCAP file into a list of PacketRecords (optionally first `limit`)."""
    records: List[PacketRecord] = []
    for rec in iter_pcap(path):
        records.append(rec)
        if limit is not None and len(records) >= limit:
            break
    return records


##########################
# Live capture (guarded) #
##########################

def capture_live(
    interface: str,
    count: int = 10,
    timeout: int = 10,
    authorized: bool = False,
    bpf_filter: Optional[str] = None,
) -> List[PacketRecord]:
    """Short live capture. Requires explicit `authorized=True`.

    Only use on an interface/traffic you own or are permitted to monitor.
    Capped at MAX_LIVE_PACKETS packets and MAX_LIVE_SECONDS seconds.
    Usually needs root/Administrator (and Npcap on Windows).
    """
    if not authorized:
        raise PermissionError(
            "Live capture requires authorized=True: confirm you are permitted to "
            "monitor this interface and its traffic."
        )
    if not (1 <= count <= MAX_LIVE_PACKETS):
        raise ValueError(f"count must be 1..{MAX_LIVE_PACKETS}")
    if not (1 <= timeout <= MAX_LIVE_SECONDS):
        raise ValueError(f"timeout must be 1..{MAX_LIVE_SECONDS} seconds")
    try:
        packets = sniff(iface=interface, count=count, timeout=timeout,
                        filter=bpf_filter, store=True)
    except (PermissionError, OSError, ValueError, Scapy_Exception) as exc:
        # ValueError = scapy's "Interface '<name>' not found"
        raise CaptureError(f"Live capture on '{interface}' failed: {exc}") from exc
    return [parse_packet(p, index=i) for i, p in enumerate(packets)]


#########################################################
# python -m backend.app.capture {interfaces|parse|live} #
#########################################################

def _print_table(records: List[PacketRecord]) -> None:
    hdr = f"{'#':>3} {'proto':<6} {'len':>5} {'src':<28} {'dst':<28} {'flags':<5} dns"
    print(hdr)
    print("-" * len(hdr))
    for r in records:
        src = f"{r.src_ip}:{r.src_port}" if r.src_ip and r.src_port is not None else (r.src_ip or "-")
        dst = f"{r.dst_ip}:{r.dst_port}" if r.dst_ip and r.dst_port is not None else (r.dst_ip or "-")
        print(f"{r.index:>3} {r.protocol:<6} {r.length:>5} {src:<28} {dst:<28} "
              f"{(r.tcp_flags or '-'):<5} {r.dns_query or '-'}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="capture", description="PacketIQ AI capture tool")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("interfaces", help="list capture interfaces")
    p_parse = sub.add_parser("parse", help="parse an offline PCAP")
    p_parse.add_argument("pcap")
    p_parse.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    p_live = sub.add_parser("live", help="short authorized live capture")
    p_live.add_argument("interface")
    p_live.add_argument("--count", type=int, default=10)
    p_live.add_argument("--timeout", type=int, default=10)
    p_live.add_argument("--i-am-authorized", action="store_true",
                        help="confirm you may monitor this interface")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "interfaces":
            for i in list_interfaces():
                print(f"{i['name']:<16} ip={i['ip'] or '-':<16} mac={i['mac'] or '-'}")
            return 0
        records = (
            read_pcap(args.pcap) if args.cmd == "parse"
            else capture_live(args.interface, args.count, args.timeout, args.i_am_authorized)
        )
    except (PcapReadError, CaptureError, PermissionError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json", False):
        print(json.dumps([r.to_dict() for r in records], indent=2))
    else:
        _print_table(records)
        print(f"\n{len(records)} packet(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
