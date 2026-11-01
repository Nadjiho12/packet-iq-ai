"""Tests for backend/app/detection.py (Week 2, tasks 2-4).

Every rule has: a positive test, a negative test, and threshold-boundary tests
(exactly-at-threshold must NOT alert; one past it must). Data is synthetic.
"""
import json
from pathlib import Path

import pytest

from backend.app.capture import read_pcap
from backend.app.detection import (RULES, SEVERITIES, Alert, DetectionEngine, Thresholds,
                                   dns_suspicion, run_detection, shannon_entropy)
from tests.synth import CLIENT, SERVER, ids, rec, scan, spoofed_syns, syn_burst

TH = Thresholds()
ROOT = Path(__file__).resolve().parent.parent
ATTACK_PCAP = ROOT / "sample_pcaps" / "attack_demo.pcap"
BENIGN_PCAP = ROOT / "sample_pcaps" / "sample.pcap"


def run(records, **kw):
    return run_detection(records, **kw).alerts


# thresholds
def test_default_thresholds_match_the_assignment():
    assert TH.port_scan_unique_ports == 20 and TH.port_scan_window_s == 10
    assert TH.volume_bytes == 10 * 1024 * 1024
    assert TH.connect_attempts == 100 and TH.connect_window_s == 5
    assert TH.dns_max_length == 50
    assert TH.syn_ratio == 0.8


def test_rule_catalogue_ids_names_and_severities():
    assert sorted(RULES) == [f"RULE-00{i}" for i in range(1, 6)]
    assert [RULES[r].name for r in sorted(RULES)] == [
        "Port Scan", "Unusual Traffic Volume", "High-Frequency Connects",
        "Suspicious DNS", "TCP SYN Flood Pattern"]
    assert all(r.severity in SEVERITIES for r in RULES.values())


# RULE-001
def test_rule001_positive_21_ports():
    alerts = run(scan(21))
    assert ids(alerts) == ["RULE-001"]
    a = alerts[0]
    assert a.severity == "medium" and a.src_ip == CLIENT and a.dst_ip == SERVER
    assert a.evidence["unique_dst_ports"] == 21 and a.evidence["threshold"] == 20


def test_rule001_boundary_exactly_20_ports_does_not_alert():
    assert run(scan(20)) == []


def test_rule001_alert_fires_on_the_21st_port_packet():
    (a,) = run(scan(30, gap=0.1))
    assert a.timestamp == pytest.approx(20 * 0.1)   # 21st packet, index 20


def test_rule001_window_boundary_inclusive_10s():
    assert ids(run(scan(21, gap=0.5))) == ["RULE-001"]   # first->last = exactly 10.0 s


def test_rule001_window_boundary_just_over_10s_does_not_alert():
    assert run(scan(21, gap=0.51)) == []                 # oldest port ages out first


def test_rule001_ports_must_be_on_one_host():
    recs = [rec(i * 0.1, dst=f"198.51.100.{i + 1}", dport=1000 + i) for i in range(30)]
    assert run(recs) == []


def test_rule001_repeated_port_is_not_unique():
    assert run([rec(i * 0.01, sport=40000, dport=80, flags="PA") for i in range(200)]) == []


def test_rule001_ports_from_different_sources_are_not_pooled():
    recs = scan(15, src="192.0.2.11") + scan(15, src="192.0.2.12", start=0.05)
    assert run(recs) == []


def test_rule001_ongoing_scan_alerts_once_per_cooldown():
    assert ids(run(scan(100, gap=0.1))).count("RULE-001") == 1   # 10 s of scanning, one alert


def test_known_limitation_large_syn_scan_also_matches_rule005():
    # A SYN scan of >= syn_min_packets ports is a burst of SYNs with no handshakes, which is
    # exactly the RULE-005 shape. The prototype cannot tell the two apart (see report).
    assert set(ids(run(scan(100, gap=0.1)))) == {"RULE-001", "RULE-005"}
    assert ids(run(scan(40, gap=0.1))) == ["RULE-001"]           # small scans stay RULE-001 only


def test_rule001_alerts_again_after_cooldown():
    recs = scan(30, gap=0.1) + scan(30, start=100.0, gap=0.1)
    assert ids(run(recs)) == ["RULE-001", "RULE-001"]


def test_rule001_missing_port_is_ignored():
    assert run([rec(i * 0.1, dport=None, proto="ICMP", flags=None) for i in range(50)]) == []


# RULE-002
def test_rule002_positive_over_10mb():
    alerts = run([rec(0.0, flags="PA", length=TH.volume_bytes), rec(1.0, flags="PA", length=1)])
    assert ids(alerts) == ["RULE-002"]
    a = alerts[0]
    assert a.severity == "medium"
    assert a.evidence["byte_count"] == TH.volume_bytes + 1
    assert a.evidence["threshold_bytes"] == TH.volume_bytes
    assert a.evidence["duration_seconds"] == pytest.approx(1.0)


def test_rule002_boundary_exactly_10mb_does_not_alert():
    assert run([rec(0.0, flags="PA", length=TH.volume_bytes)]) == []


def test_rule002_is_per_flow_not_per_host():
    half = TH.volume_bytes // 2 + 10
    assert run([rec(0.0, sport=1, flags="PA", length=half), rec(0.1, sport=2, flags="PA", length=half)]) == []


def test_rule002_directions_are_counted_separately():
    half = TH.volume_bytes // 2 + 10
    assert run([rec(0.0, CLIENT, SERVER, 1, 2, flags="PA", length=half),
                rec(0.1, SERVER, CLIENT, 2, 1, flags="PA", length=half)]) == []


def test_rule002_alerts_once_per_flow():
    recs = [rec(i, flags="PA", length=TH.volume_bytes // 2) for i in range(10)]
    assert ids(run(recs)) == ["RULE-002"]


def test_rule002_works_without_timestamps():
    alerts = run([rec(None, flags="PA", length=TH.volume_bytes + 1)])
    assert ids(alerts) == ["RULE-002"] and alerts[0].timestamp is None


def test_rule002_invalid_lengths_count_as_zero():
    assert run([rec(i, flags="PA", length=-10 ** 9) for i in range(5)] +
               [rec(9, flags="PA", length="huge")]) == []


# RULE-003
def test_rule003_positive_101_attempts_in_5s():
    alerts = run(syn_burst(101, gap=0.04))          # spans 4.0 s
    assert "RULE-003" in ids(alerts)
    a = next(a for a in alerts if a.rule_id == "RULE-003")
    assert a.severity == "high" and a.evidence["connection_attempts"] == 101
    assert a.evidence["threshold"] == 100 and a.evidence["window_seconds"] == 5


def test_rule003_boundary_exactly_100_attempts_does_not_alert():
    assert "RULE-003" not in ids(run(syn_burst(100, gap=0.04)))


def test_rule003_window_just_over_5s_does_not_alert():
    # 101 attempts spaced 0.0505 s apart: the first one has aged out when the 101st arrives
    assert "RULE-003" not in ids(run(syn_burst(101, gap=0.0505)))


def test_rule003_window_exactly_5s_alerts():
    assert "RULE-003" in ids(run(syn_burst(101, gap=0.05)))     # first - last = 5.0 s


def test_rule003_plain_acks_are_not_connection_attempts():
    assert run([rec(i * 0.01, sport=1024 + i, flags="A") for i in range(300)]) == []


def test_rule003_synacks_are_not_connection_attempts():
    assert run([rec(i * 0.01, sport=1024 + i, flags="SA") for i in range(300)]) == []


def test_rule003_new_udp_flows_count_as_attempts():
    recs = [rec(i * 0.01, sport=2000 + i, dport=9999, proto="UDP", flags=None) for i in range(101)]
    assert ids(run(recs)) == ["RULE-003"]


def test_rule003_one_long_udp_flow_is_one_attempt():
    recs = [rec(i * 0.01, sport=2000, dport=9999, proto="UDP", flags=None) for i in range(300)]
    assert run(recs) == []


def test_rule003_attempts_are_counted_per_destination():
    recs = syn_burst(60, dst="198.51.100.21") + syn_burst(60, dst="198.51.100.22", start=0.005)
    assert "RULE-003" not in ids(run(recs))


def test_rule003_completed_handshakes_do_not_trigger_rule005():
    recs = []
    for i in range(130):
        recs.append(rec(i * 0.02, sport=1024 + i, flags="S"))
        recs.append(rec(i * 0.02 + 0.005, sport=1024 + i, flags="A"))
    assert ids(run(recs)) == ["RULE-003"]


# RULE-004
LONG51 = "q" * 39 + ".example.com"          # 51 chars (q is not a hex digit)
LONG50 = "q" * 38 + ".example.com"          # 50 chars


def test_rule004_positive_query_longer_than_50():
    assert len(LONG51) == 51
    alerts = run([rec(1.0, CLIENT, "192.0.2.53", 5300, 53, "DNS", None, dns=LONG51)])
    assert ids(alerts) == ["RULE-004"]
    a = alerts[0]
    assert a.severity == "medium" and "query_length>50" in a.evidence["reasons"]
    assert a.evidence["query"] == LONG51 and a.evidence["query_length"] == 51


def test_rule004_boundary_exactly_50_chars_does_not_alert():
    assert len(LONG50) == 50
    assert run([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None, dns=LONG50)]) == []


def test_rule004_trailing_dot_is_not_counted():
    assert run([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None, dns=LONG50 + ".")]) == []


def test_rule004_positive_high_entropy_label_even_when_short():
    q = "x7k2q9m4z8p1w5v3n6.exfil.example"
    assert len(q) <= 50
    (a,) = run([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None, dns=q)])
    assert a.rule_id == "RULE-004" and a.evidence["reasons"] == ["high_entropy_label"]


def test_rule004_positive_hex_encoded_label():
    q = "deadbeef" * 5 + ".example.com"
    (a,) = run([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None, dns=q)])
    assert "hex_encoded_label" in a.evidence["reasons"]


def test_rule004_positive_digit_heavy_label():
    (a,) = run([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None, dns="1234567890123.example")])
    assert a.evidence["reasons"] == ["digit_heavy_label"]


@pytest.mark.parametrize("name", [
    "example.com", "www.google.com", "mail.internal.corp.example.org",
    "internationalization.example.com", "kubernetes-dashboard-service.example.com",
    "d111111abcdef8.cloudfront.net", "_dmarc.example.com", "a.b", "localhost"])
def test_rule004_negative_ordinary_names(name):
    assert run([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None, dns=name)]) == []


def test_rule004_responses_are_not_judged():
    assert run([rec(1.0, SERVER, CLIENT, 53, 5300, "DNS", None, dns=LONG51)]) == []


def test_rule004_same_query_alerts_once():
    recs = [rec(i, sport=5300 + i, dport=53, proto="DNS", flags=None, dns=LONG51) for i in range(5)]
    assert ids(run(recs)) == ["RULE-004"]


def test_rule004_works_without_timestamp():
    (a,) = run([rec(None, sport=5300, dport=53, proto="DNS", flags=None, dns=LONG51)])
    assert a.timestamp is None and a.timestamp_iso is None


@pytest.mark.parametrize("dns", [None, "", "   ", 12345, ["x"], {"q": 1}, b"", b"\xff\xfe"])
def test_rule004_unexpected_query_values_do_not_crash(dns):
    eng = run_detection([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None, dns=dns)])
    assert eng.stats["internal_errors"] == 0


def test_rule004_bytes_query_is_decoded():
    assert ids(run([rec(1.0, sport=5300, dport=53, proto="DNS", flags=None,
                        dns=LONG51.encode())])) == ["RULE-004"]


def test_dns_helpers():
    assert shannon_entropy("") == 0.0 and shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert dns_suspicion("example.com", TH)[0] == []


# RULE-005
def test_rule005_positive_flood_from_many_sources():
    alerts = run(spoofed_syns(100))
    assert ids(alerts) == ["RULE-005"]
    a = alerts[0]
    assert a.severity == "high" and a.dst_ip == SERVER and a.src_ip is None
    e = a.evidence
    assert e["syn_ratio"] == 1.0 and e["established_flows"] == 0 and e["threshold_ratio"] == 0.8
    assert e["syn_without_ack_packets"] == e["total_tcp_packets"] >= TH.syn_min_packets


def test_rule005_negative_completed_handshakes():
    recs = []
    for i in range(100):
        recs += [rec(i * 0.02, f"203.0.113.{i + 1}", sport=2000 + i, flags="S"),
                 rec(i * 0.02 + 0.005, f"203.0.113.{i + 1}", sport=2000 + i, flags="A")]
    assert run(recs) == []


def _background(n, start=0.0):
    """n non-SYN TCP packets to SERVER from distinct hosts (no SYN seen, so never half-open)."""
    return [rec(start + i * 0.001, f"192.0.2.{i + 100}", sport=3000 + i, flags="PA") for i in range(n)]


def test_rule005_boundary_ratio_exactly_80_percent_does_not_alert():
    recs = _background(20) + spoofed_syns(80, start=0.1)     # 80 / 100 = 0.80, not > 0.80
    assert run(recs) == []


def test_rule005_boundary_one_more_syn_alerts():
    recs = _background(20) + spoofed_syns(81, start=0.1)     # 81 / 101 = 0.802 > 0.80
    (a,) = run(recs)
    assert a.rule_id == "RULE-005"
    assert a.evidence["syn_ratio"] > 0.8
    assert a.evidence["total_tcp_packets"] == 101


def _completed_handshakes(n, start=0.0):
    """n complete handshakes to SERVER (SYN then ACK on the same flow) from distinct hosts."""
    out = []
    for i in range(n):
        src = f"192.0.2.{i + 100}"
        out += [rec(start + i * 0.002, src, sport=3000 + i, flags="S"),
                rec(start + i * 0.002 + 0.001, src, sport=3000 + i, flags="A")]
    return out


def test_rule005_established_flows_are_excluded_from_the_ratio():
    # 15 completed handshakes + 85 half-open SYNs: raw SYN share is 100/115 = 0.87, but only
    # 85/115 = 0.74 of the packets are half-open SYNs, so there is no flood.
    assert run(_completed_handshakes(15) + spoofed_syns(85, start=0.1)) == []


def test_rule005_exact_ratio_boundary_with_established_flows():
    # 12 handshakes (24 packets) + 96 half-open SYNs: 96/120 = 0.80 exactly -> no alert.
    assert run(_completed_handshakes(12) + spoofed_syns(96, start=0.1)) == []
    # One more half-open SYN: 97/121 = 0.802 -> alert, and the evidence shows established flows.
    (a,) = run(_completed_handshakes(12) + spoofed_syns(97, start=0.1))
    assert a.rule_id == "RULE-005" and a.evidence["established_flows"] == 12
    assert a.evidence["syn_without_ack_packets"] == 97 and a.evidence["total_tcp_packets"] == 121


def test_rule005_minimum_applies_to_half_open_syns_not_raw_syns():
    # 5 completed handshakes + 45 half-open SYNs: 50 raw SYNs, ratio 45/55 = 0.82, but only
    # 45 half-open SYNs (< 50), so the minimum-sample guard holds.
    assert run(_completed_handshakes(5) + spoofed_syns(45, start=0.1)) == []


def test_rule005_boundary_minimum_syn_count():
    assert run(spoofed_syns(TH.syn_min_packets - 1)) == []
    assert ids(run(spoofed_syns(TH.syn_min_packets))) == ["RULE-005"]


def test_rule005_syns_spread_beyond_window_do_not_alert():
    assert run(spoofed_syns(100, gap=0.3)) == []     # at most ~34 SYNs inside any 10 s window


def test_rule005_mixed_legitimate_traffic_dilutes_ratio():
    recs = spoofed_syns(60)
    for i in range(60):                               # 60 completed handshakes in the same window
        recs += [rec(0.2 + i * 0.01, f"192.0.2.{i + 100}", sport=3000 + i, flags="S"),
                 rec(0.205 + i * 0.01, f"192.0.2.{i + 100}", sport=3000 + i, flags="A")]
    assert run(recs) == []                            # 60 half-open / 180 packets


def test_rule005_per_destination():
    recs = spoofed_syns(30, dst="198.51.100.21") + spoofed_syns(30, dst="198.51.100.22")
    assert run(recs) == []


def test_rule005_ignores_non_tcp_traffic():
    recs = [rec(i * 0.01, f"203.0.113.{i + 1}", sport=2000 + i, proto="UDP", flags=None) for i in range(200)]
    assert "RULE-005" not in ids(run(recs))


def test_rule005_null_flag_tcp_packets_are_not_syns():
    assert run([rec(i * 0.01, f"203.0.113.{i + 1}", sport=2000 + i, flags="") for i in range(200)]) == []


# consistency
def mixed_scenario():
    recs = scan(30, start=0)
    recs += syn_burst(120, start=20, gap=0.02, src="192.0.2.77")
    recs += spoofed_syns(100, start=40, dst="198.51.100.99")
    recs += [rec(60, "192.0.2.5", "198.51.100.5", 1, 443, flags="PA", length=TH.volume_bytes + 1)]
    recs += [rec(70, sport=5300, dport=53, proto="DNS", flags=None, dns=LONG51)]
    return recs


def test_every_rule_fires_on_the_mixed_scenario():
    assert {a.rule_id for a in run(mixed_scenario())} == set(RULES)


def test_alert_records_are_consistent():
    alerts = run(mixed_scenario())
    keys = None
    for a in alerts:
        info = RULES[a.rule_id]
        assert (a.rule_name, a.severity) == (info.name, info.severity)
        assert a.severity in SEVERITIES
        assert a.summary and isinstance(a.evidence, dict) and a.evidence
        assert a.timestamp is not None and a.timestamp_iso.endswith("+00:00")
        d = a.to_dict()
        keys = keys or set(d)
        assert set(d) == keys == {"rule_id", "rule_name", "severity", "timestamp", "timestamp_iso",
                                  "src_ip", "dst_ip", "summary", "evidence"}
        json.dumps(d)                                  # must be JSON-serialisable


def test_alert_timestamps_are_packet_times_not_wall_clock():
    (a,) = run(scan(21, start=1000.0, gap=0.1))
    assert a.timestamp == pytest.approx(1002.0)


def test_results_are_repeatable():
    first = [a.to_dict() for a in run(mixed_scenario())]
    second = [a.to_dict() for a in run(mixed_scenario())]
    assert first == second


def test_unsorted_input_is_sorted_by_run_detection():
    recs = scan(21)
    assert ids(run(list(reversed(recs)))) == ["RULE-001"]


def test_custom_thresholds_are_honoured():
    th = Thresholds(port_scan_unique_ports=5)
    assert ids(run(scan(6), thresholds=th)) == ["RULE-001"]


# robustness
GARBAGE = [None, {}, [], "str", 7, object(), {"src_ip": 5}, {"timestamp": "x"},
           {"src_ip": CLIENT, "dst_ip": SERVER, "protocol": "TCP", "tcp_flags": {"x": 1},
            "dst_port": "http", "length": None, "timestamp": float("nan"), "dns_query": 3},
           rec(float("inf")), rec(-1.0), rec(1e308), rec(None, flags="ZZ")]


def test_garbage_input_never_crashes_and_never_alerts():
    eng = run_detection(GARBAGE)
    assert eng.stats["internal_errors"] == 0
    assert eng.alerts == []
    assert eng.stats["packets_processed"] == len(GARBAGE)


def test_streaming_api_returns_new_alerts_only():
    eng = DetectionEngine()
    got = []
    for r in scan(25):
        got += eng.process(r)
    assert ids(got) == ["RULE-001"] and eng.alerts == got


def test_packets_without_timestamps_skip_windowed_rules():
    eng = run_detection([dict(r, timestamp=None) for r in scan(50)])
    assert eng.alerts == [] and eng.stats["packets_without_timestamp"] == 50


def test_backwards_timestamps_do_not_crash_in_streaming_mode():
    eng = DetectionEngine()
    for r in reversed(scan(30)):
        eng.process(r)
    assert eng.stats["internal_errors"] == 0


# end to end
def test_pipeline_attack_pcap_triggers_all_five_rules_once_each():
    alerts = run(read_pcap(ATTACK_PCAP))
    by_rule = {}
    for a in alerts:
        by_rule.setdefault(a.rule_id, []).append(a)
    assert set(by_rule) == set(RULES)
    assert all(len(by_rule[r]) == 1 for r in ("RULE-001", "RULE-002", "RULE-003", "RULE-005"))
    assert len(by_rule["RULE-004"]) == 2
    assert by_rule["RULE-001"][0].src_ip == "198.51.100.77"
    assert by_rule["RULE-003"][0].src_ip == "198.51.100.88"
    assert by_rule["RULE-005"][0].dst_ip == "192.0.2.30"
    assert by_rule["RULE-002"][0].src_ip == "192.0.2.40"
    assert by_rule["RULE-002"][0].evidence["byte_count"] > TH.volume_bytes


def test_pipeline_benign_week1_sample_raises_no_alerts():
    eng = run_detection(read_pcap(BENIGN_PCAP))
    assert eng.alerts == [] and eng.stats["internal_errors"] == 0
    assert eng.flows.stats["records_skipped_no_flow_key"] == 2     # ARP + raw Ethernet frame: no IPs
