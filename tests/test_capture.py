"""Tests for backend/app/capture.py

Most tests read the synthetic sample PCAP (indices documented in
scripts/make_sample_pcap.py). A few build packets in memory to exercise
missing-layer / malformed cases. Live capture is skipped unless
PACKETIQ_LIVE_TEST=1 and PACKETIQ_LIVE_IFACE is set (authorized lab only).
"""
import os
from pathlib import Path

import pytest
from scapy.all import ARP, IP, TCP, Ether, Raw, wrpcap

from backend.app.capture import (
    CaptureError,
    PacketRecord,
    PcapReadError,
    capture_live,
    list_interfaces,
    parse_packet,
    read_pcap,
)

SAMPLE = Path(__file__).resolve().parent.parent / "sample_pcaps" / "sample.pcap"
FIELDS = set(PacketRecord.__dataclass_fields__)


@pytest.fixture(scope="module")
def recs():
    return read_pcap(SAMPLE)


# offline read

def test_sample_parses_without_errors(recs):
    assert len(recs) == 12
    assert all(r.parse_error is None for r in recs)
    assert [r.index for r in recs] == list(range(12))


def test_every_record_has_identical_keys(recs):
    assert all(set(r.to_dict()) == FIELDS for r in recs)


def test_timestamps_are_ordered_and_iso(recs):
    ts = [r.timestamp for r in recs]
    assert ts == sorted(ts)
    assert ts[1] - ts[0] == pytest.approx(0.25, abs=1e-3)
    assert recs[0].timestamp_iso.endswith("+00:00")


# TCP

def test_tcp_syn_fields(recs):
    r = recs[0]
    assert (r.src_ip, r.dst_ip, r.ip_version) == ("192.0.2.10", "198.51.100.20", 4)
    assert (r.protocol, r.src_port, r.dst_port, r.tcp_flags) == ("TCP", 49152, 80, "S")
    assert r.dns_query is None


def test_tcp_flag_strings(recs):
    assert recs[1].tcp_flags == "SA"
    assert recs[2].tcp_flags == "PA"


def test_packet_lengths(recs):
    assert recs[0].length == 54      # Ether14 + IP20 + TCP20
    assert recs[2].length == 54 + len(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert recs[5].length == 14 + 20 + 8 + 5   # Ether + IP + UDP + "hello"


# DNS

def test_dns_query_extracted(recs):
    r = recs[3]
    assert r.protocol == "DNS"
    assert (r.src_port, r.dst_port) == (53000, 53)
    assert r.dns_query == "example.com"          # decoded, no trailing dot
    assert r.tcp_flags is None


def test_dns_response_keeps_question_name(recs):
    r = recs[4]
    assert (r.protocol, r.src_port, r.dst_port) == ("DNS", 53, 53000)
    assert r.dns_query == "example.com"


# UDP / ICMP / v6

def test_plain_udp(recs):
    r = recs[5]
    assert (r.protocol, r.src_port, r.dst_port) == ("UDP", 40000, 9999)
    assert r.tcp_flags is None and r.dns_query is None


def test_icmp_has_no_ports(recs):
    r = recs[6]
    assert r.protocol == "ICMP"
    assert r.src_port is None and r.dst_port is None and r.tcp_flags is None


def test_ipv6_tcp(recs):
    r = recs[8]
    assert (r.ip_version, r.src_ip, r.dst_ip) == (6, "2001:db8::1", "2001:db8::2")
    assert (r.protocol, r.dst_port, r.tcp_flags) == ("TCP", 443, "S")


def test_icmpv6(recs):
    r = recs[9]
    assert (r.protocol, r.ip_version) == ("ICMPv6", 6)
    assert r.src_port is None


# missing layers / non-IP

def test_arp_is_non_ip(recs):
    r = recs[7]
    assert r.protocol == "ARP"
    assert r.src_ip is None and r.dst_ip is None and r.ip_version is None
    assert r.src_port is None and r.dst_port is None


def test_ip_without_known_transport(recs):
    r = recs[10]
    assert r.protocol == "OTHER"
    assert (r.src_ip, r.dst_ip) == ("192.0.2.10", "198.51.100.20")
    assert r.src_port is None and r.tcp_flags is None


def test_ethernet_frame_without_ip(recs):
    r = recs[11]
    assert r.protocol == "OTHER"
    assert r.src_ip is None and r.dst_ip is None and r.ip_version is None


def test_truncated_tcp_does_not_raise():
    raw = bytes(Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP())[:-10]
    r = parse_packet(Ether(raw))
    assert r.parse_error is None
    assert r.src_ip == "192.0.2.1"
    assert set(r.to_dict()) == FIELDS


def test_bare_payload_without_any_layer():
    r = parse_packet(Raw(b"\x00\x01\x02"))
    assert r.protocol == "OTHER"
    assert r.src_ip is None and r.length == 3


def test_parse_packet_never_raises_on_bad_object():
    r = parse_packet(object())          # not a scapy packet at all
    assert r.parse_error is not None
    assert r.protocol == "OTHER" and r.length == 0


def test_hand_built_arp_packet():
    r = parse_packet(Ether() / ARP(psrc="192.0.2.5", pdst="192.0.2.6"))
    assert r.protocol == "ARP" and r.src_ip is None


# file-level errors

def test_missing_file_raises():
    with pytest.raises(PcapReadError):
        read_pcap("does_not_exist.pcap")


def test_non_pcap_file_raises(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a pcap file")
    with pytest.raises(PcapReadError):
        read_pcap(bad)


def test_empty_pcap_returns_empty_list(tmp_path):
    empty = tmp_path / "empty.pcap"
    wrpcap(str(empty), [])
    assert read_pcap(empty) == []


def test_limit_argument():
    assert len(read_pcap(SAMPLE, limit=3)) == 3


# interfaces/live

def test_list_interfaces_shape():
    ifaces = list_interfaces()
    assert isinstance(ifaces, list) and ifaces
    assert all({"name", "description", "ip", "mac"} <= set(i) for i in ifaces)
    assert all(i["name"] for i in ifaces)


def test_live_capture_requires_authorization():
    with pytest.raises(PermissionError):
        capture_live("lo")


@pytest.mark.parametrize("count,timeout", [(0, 5), (5000, 5), (5, 0), (5, 600)])
def test_live_capture_enforces_limits(count, timeout):
    with pytest.raises(ValueError):
        capture_live("lo", count=count, timeout=timeout, authorized=True)


def test_live_capture_bad_interface_gives_capture_error():
    with pytest.raises(CaptureError):
        capture_live("no_such_iface0", count=1, timeout=1, authorized=True)


@pytest.mark.skipif(
    not (os.getenv("PACKETIQ_LIVE_TEST") == "1" and os.getenv("PACKETIQ_LIVE_IFACE")),
    reason="live capture is opt-in: set PACKETIQ_LIVE_TEST=1 and PACKETIQ_LIVE_IFACE (authorized lab only)",
)
def test_live_capture_short_authorized():
    recs = capture_live(os.environ["PACKETIQ_LIVE_IFACE"], count=5, timeout=5, authorized=True)
    assert len(recs) <= 5
    assert all(set(r.to_dict()) == FIELDS for r in recs)
