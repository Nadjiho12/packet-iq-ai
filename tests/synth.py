"""Synthetic packet-record builders shared by the Week 2 tests.

Records are plain dicts with the same keys as capture.PacketRecord.to_dict(),
so the tests never touch the network or a PCAP (except the pipeline tests).
"""
from typing import Any, Dict, List, Optional

CLIENT, SERVER = "192.0.2.10", "198.51.100.20"


def rec(ts: Optional[float], src: str = CLIENT, dst: str = SERVER, sport: Optional[int] = 40000,
        dport: Optional[int] = 80, proto: str = "TCP", flags: Optional[str] = "S",
        length: int = 60, dns: Optional[str] = None) -> Dict[str, Any]:
    return {"timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "tcp_flags": flags, "length": length, "dns_query": dns}


def syn_burst(n: int, start: float = 0.0, gap: float = 0.01, src: str = CLIENT,
              dst: str = SERVER, dport: int = 80) -> List[Dict[str, Any]]:
    """n SYN-only packets, one new source port each (n new connection attempts)."""
    return [rec(start + i * gap, src, dst, 1024 + i, dport, flags="S") for i in range(n)]


def scan(n_ports: int, start: float = 0.0, gap: float = 0.1, src: str = CLIENT,
         dst: str = SERVER) -> List[Dict[str, Any]]:
    return [rec(start + i * gap, src, dst, 44000, 1000 + i, flags="S") for i in range(n_ports)]


def spoofed_syns(n: int, start: float = 0.0, gap: float = 0.01,
                 dst: str = SERVER) -> List[Dict[str, Any]]:
    """n SYN-only packets, each from a different source address (a flood shape)."""
    return [rec(start + i * gap, f"203.0.113.{i % 250 + 1}", dst, 2000 + i, 80, flags="S")
            for i in range(n)]


def ids(alerts) -> List[str]:
    return [a.rule_id for a in alerts]
