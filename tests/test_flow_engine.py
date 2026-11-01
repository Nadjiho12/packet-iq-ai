"""Tests for backend/app/flow_engine.py (Week 2, task 1)."""

import pytest

from backend.app.capture import PacketRecord
from backend.app.flow_engine import FlowEngine, FlowKey, normalize_packet, parse_tcp_flags
from tests.synth import CLIENT, SERVER, rec


def test_flow_key_has_exactly_the_five_required_fields():
    assert FlowKey._fields == ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")
    eng = FlowEngine()
    eng.update(rec(1.0, sport=4000, dport=80))
    assert list(eng.flows) == [FlowKey(CLIENT, SERVER, 4000, 80, "TCP")]


def test_counters_and_timestamps_accumulate():
    eng = FlowEngine()
    for ts, length in [(5.0, 100), (7.5, 200), (6.0, 300)]:   # includes an out-of-order packet
        eng.update(rec(ts, flags="PA", length=length))
    (flow,) = eng.flows.values()
    assert flow.packet_count == 3
    assert flow.byte_count == 600
    assert flow.first_seen == 5.0 and flow.last_seen == 7.5
    assert flow.duration == pytest.approx(2.5)
    assert flow.dst_port == 80


def test_first_packet_creates_flow_and_later_ones_do_not():
    eng = FlowEngine()
    assert eng.update(rec(1.0)).is_new is True
    assert eng.update(rec(2.0)).is_new is False
    assert eng.stats["flows_created"] == 1


def test_different_tuple_fields_make_different_flows():
    eng = FlowEngine()
    eng.update(rec(1.0, sport=4000))
    eng.update(rec(1.0, sport=4001))                 # src_port differs
    eng.update(rec(1.0, dport=443))                  # dst_port differs
    eng.update(rec(1.0, proto="UDP", flags=None))    # protocol differs
    eng.update(rec(1.0, dst="198.51.100.21"))        # dst_ip differs
    eng.update(rec(1.0, src="192.0.2.11"))           # src_ip differs
    assert len(eng.flows) == 6


def test_flows_are_directional():
    eng = FlowEngine()
    eng.update(rec(1.0, CLIENT, SERVER, 4000, 80))
    eng.update(rec(1.1, SERVER, CLIENT, 80, 4000, flags="SA"))
    assert len(eng.flows) == 2


def test_destination_ports_per_host_pair():
    eng = FlowEngine()
    for p in (22, 80, 443, 80):
        eng.update(rec(1.0, dport=p))
    eng.update(rec(1.0, dst="198.51.100.99", dport=8080))
    assert eng.dst_ports_for(CLIENT, SERVER) == {22, 80, 443}
    assert eng.dst_ports_for(CLIENT, "198.51.100.99") == {8080}
    assert eng.dst_ports_for("203.0.113.1", SERVER) == set()


def test_tcp_flag_tracking_and_handshake_completion():
    eng = FlowEngine()
    eng.update(rec(1.0, flags="S"))
    (flow,) = eng.flows.values()
    assert flow.syn_count == 1 and not flow.established
    eng.update(rec(1.1, flags="A"))
    assert flow.established and flow.ack_after_syn
    assert flow.tcp_flags_seen == "SA"
    assert flow.flag_counts == {"S": 1, "A": 1}


def test_synack_alone_does_not_establish_a_flow():
    eng = FlowEngine()
    eng.update(rec(1.0, flags="S"))
    eng.update(rec(1.1, flags="SA"))
    assert not list(eng.flows.values())[0].established


def test_ack_without_prior_syn_is_not_established():
    eng = FlowEngine()
    eng.update(rec(1.0, flags="PA"))
    assert not list(eng.flows.values())[0].established


def test_icmp_flow_has_none_ports():
    eng = FlowEngine()
    eng.update(rec(1.0, sport=None, dport=None, proto="ICMP", flags=None))
    (key,) = eng.flows
    assert key.src_port is None and key.dst_port is None


def test_accepts_packetrecord_objects_and_dicts():
    pr = PacketRecord(index=0, timestamp=3.0, timestamp_iso=None, length=70, src_ip=CLIENT,
                      dst_ip=SERVER, ip_version=4, protocol="TCP", src_port=1, dst_port=2,
                      tcp_flags="S", dns_query=None)
    eng = FlowEngine()
    eng.update(pr)
    eng.update(pr.to_dict())
    (flow,) = eng.flows.values()
    assert flow.packet_count == 2 and flow.byte_count == 140


# robustness
@pytest.mark.parametrize("bad", [
    None, {}, [], "text", 42, {"src_ip": "not-an-ip", "dst_ip": SERVER, "protocol": "TCP"},
    {"src_ip": CLIENT, "dst_ip": None, "protocol": "TCP"},
    {"src_ip": CLIENT, "dst_ip": SERVER, "protocol": ""},
    {"src_ip": 5, "dst_ip": SERVER, "protocol": "TCP"},
])
def test_unusable_records_are_counted_not_raised(bad):
    eng = FlowEngine()
    upd = eng.update(bad)
    assert upd.flow is None
    assert eng.stats["records_skipped_no_flow_key"] == 1
    assert not eng.flows


@pytest.mark.parametrize("ts", [None, float("nan"), float("inf"), -5, "abc", True, [1]])
def test_bad_timestamps_become_none_but_flow_still_counts(ts):
    eng = FlowEngine()
    eng.update(rec(ts, length=50))
    (flow,) = eng.flows.values()
    assert flow.packet_count == 1 and flow.byte_count == 50
    assert flow.first_seen is None and flow.last_seen is None and flow.duration == 0.0
    assert eng.stats["records_without_timestamp"] == 1


@pytest.mark.parametrize("length, expected", [(-1, 0), (None, 0), ("x", 0), (True, 0),
                                              (float("nan"), 0), ("120", 120), (99.9, 99)])
def test_unexpected_lengths_are_sanitised(length, expected):
    assert normalize_packet(rec(1.0, length=length)).length == expected


@pytest.mark.parametrize("port, expected", [(80, 80), ("443", 443), (-1, None), (70000, None),
                                            (True, None), ("x", None), (None, None), (1.5, None)])
def test_ports_are_validated(port, expected):
    assert normalize_packet(rec(1.0, dport=port)).dst_port == expected


@pytest.mark.parametrize("raw, expected", [("S", "S"), ("sa", "SA"), ("AS", "SA"), ("", ""),
                                           (0x12, "SA"), (2, "S"), (0, ""), ("Z", None),
                                           (None, None), (True, None), (999, None), (3.5, None)])
def test_tcp_flag_parsing(raw, expected):
    assert parse_tcp_flags(raw) == expected


def test_missing_timestamp_flow_then_timestamp_flow():
    eng = FlowEngine()
    eng.update(rec(None))
    eng.update(rec(9.0))
    (flow,) = eng.flows.values()
    assert flow.packet_count == 2 and flow.first_seen == 9.0 == flow.last_seen
