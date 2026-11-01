# PacketIQ AI: Week 2 Report, Flow Aggregation & Detection Engine

**Program:** AeroVerix Security, PacketIQ AI Technical Internship
**Assigned:** 29 October 2026 · **Deadline:** 3 November 2026, 11:59 PM PKT
## 1. Objective

Turn parsed packets (the Week 1 `PacketRecord` format) into stateful 5-tuple flows, and implement the five heuristic detection rules (RULE-001 to RULE-005) with consistent alert objects.

## 2. Deliverables

| Deliverable | Location |
|---|---|
| Flow engine | `backend/app/flow_engine.py` |
| Detection engine (5 rules) | `backend/app/detection.py` |
| Unit tests | `tests/test_flow_engine.py` (55), `tests/test_detection.py` (84) |
| Shared synthetic-data helpers | `tests/synth.py` |
| Synthetic attack PCAP + generator | `sample_pcaps/attack_demo.pcap`, `scripts/make_attack_pcap.py` |
| Example alert records | `evidence/example_alerts.json` (section 6) |
| Test and CLI output | `evidence/week2_pytest_output_linux.txt`, `evidence/week2_detection_cli_output.txt` |

## 3. Flow state (`flow_engine.py`)

**Flow key (exactly the five required fields):** `(src_ip, dst_ip, src_port, dst_port, protocol)`. Flows are directional: A→B and B→A are separate flows. `protocol` is the Week 1 label (`TCP`, `UDP`, `DNS`, `ICMP`, ...). ICMP flows have `None` ports.

| Field | Meaning |
|---|---|
| `first_seen` / `last_seen` | smallest / largest valid timestamp (robust to out-of-order packets) |
| `packet_count` / `byte_count` | packets and on-wire bytes (`length` from Week 1) |
| `dst_port` | destination port (from the key); `FlowEngine.dst_ports_for(src, dst)` returns all ports a source contacted on a host |
| `flag_counts`, `tcp_flags_seen` | per-flag counters (`S`, `A`, `P`, `F`, `R`, ...) |
| `syn_count` | packets with SYN and no ACK (connection attempts) |
| `synack_count` | packets with SYN+ACK |
| `ack_after_syn` / `established` | an ACK (no SYN/RST) arrived after a SYN on this flow = handshake completed |

**Input handling.** Every record is normalised first. Missing or unexpected values become `None` (length becomes 0); a record without a valid `src_ip`, `dst_ip` and `protocol` forms no flow and is counted in `FlowEngine.stats` instead of raising. The engine accepts `PacketRecord` objects and plain dicts.

## 4. Detection rules (`detection.py`)

All comparisons are strict (`>`): a value exactly at a threshold does **not** alert. All values are in one `Thresholds` dataclass.

### 1- Thresholds

| Rule | Name | Severity | Threshold (from the assignment) |
|---|---|---|---|
| RULE-001 | Port Scan | medium | > 20 unique destination ports on one host within 10 s |
| RULE-002 | Unusual Traffic Volume | medium | > 10 MB in one flow |
| RULE-003 | High-Frequency Connects | high | > 100 connection attempts to one destination within 5 s |
| RULE-004 | Suspicious DNS | medium | query length > 50 characters, or suspicious pattern |
| RULE-005 | TCP SYN Flood Pattern | high | SYN ratio > 80% without corresponding established ACK state |

Each rule has one fixed severity so rule ID and severity are always consistent (tested).

### 2- Assumptions and prototype parameters (not specified in the assignment)

| Item | Choice | Why |
|---|---|---|
| "10 MB" | 10 × 1024 × 1024 = 10,485,760 bytes | binary megabyte; one constant (`Thresholds.volume_bytes`), easy to change to 10,000,000 |
| Severities | fixed per rule (table above) | assignment requires severities but does not give values |
| Window edges | inclusive: an event stays in a W-second window while `now − event ≤ W` | deterministic, tested at the boundary |
| RULE-001 scope | per (source, destination host) pair | "on one host"; ports counted for any protocol with a destination port |
| RULE-003 scope | per (source, destination IP) pair | "to one destination" |
| RULE-005 window | 10 s | ratio needs a window; none was given |
| RULE-005 minimum | at least 50 half-open SYN packets | avoids "1 SYN out of 1 packet = 100%". Also keeps small port scans (21 to 49 SYNs) from matching RULE-005 |
| RULE-004 patterns | length > 50; high-entropy label (label ≥ 16 chars with letters and digits and entropy ≥ 3.5 bits/char); hex-only label ≥ 32 chars; digit-heavy label (≥ 12 chars, ≥ 60% digits) | "suspicious pattern" is not defined; these are common tunnelling/DGA indicators |
| De-duplication | same (rule, key) alerts once per 60 s of packet time; RULE-002 once per flow; RULE-004 once per (source, query) | an ongoing scan must not alert on every packet |

### 3- How each rule works

- **RULE-001.** Per (src, dst): a sliding 10 s window of destination ports with an O(1) unique count. Alerts when unique > 20.
- **RULE-002.** Per directional flow: alerts when `byte_count` > threshold, once per flow. A flow's bytes are not pooled with other flows or with the reverse direction.
- **RULE-003.** Per (src, dst IP): counts *connection attempts* in a sliding 5 s window. An attempt is a TCP packet with SYN and no ACK, or the first packet of a non-TCP flow. Plain ACKs and SYN-ACKs do not count.
- **RULE-004.** Evaluates DNS queries only. Packets from source port 53 are treated as responses and skipped, because a response repeats the question. Query names are lower-cased and the trailing dot is removed before measuring length.
- **RULE-005.** Per destination host, over TCP packets in a 10 s window. A SYN counts as *half-open* if its flow never completed a handshake (`ack_after_syn` false). Alert when `half-open SYNs / all TCP packets to that host > 0.8` and half-open SYNs ≥ 50. Completed handshakes therefore both leave the numerator and add their ACK packets to the denominator.

## 5. Pipeline (task 4)

`capture.read_pcap()` → `PacketRecord` list → `run_detection()` (sorts by timestamp) → `DetectionEngine.process()` for each record: `FlowEngine.update()` then the five rules. Command line:

```
python -m backend.app.detection sample_pcaps/attack_demo.pcap          # table
python -m backend.app.detection sample_pcaps/attack_demo.pcap --json   # alert records
```

`attack_demo.pcap` (1,702 synthetic packets, RFC 5737 addresses) contains one scenario per rule plus benign handshakes and a DNS lookup. Result: exactly one alert for RULE-001, -002, -003, -005 and two for RULE-004, each attributed to the intended host, and **zero alerts** on the benign Week 1 `sample.pcap`. The RULE-002 flow is a header-only (snaplen-truncated) capture whose records keep their original wire length (9000 bytes), so the file is 119 KB instead of 10 MB.

## 6. Example alert records

All alerts have the same nine keys: `rule_id`, `rule_name`, `severity`, `timestamp`, `timestamp_iso`, `src_ip`, `dst_ip`, `summary`, `evidence`. Timestamps are packet times, not wall-clock times. Full file: `evidence/example_alerts.json`.

```json
{
  "rule_id": "RULE-003",
  "rule_name": "High-Frequency Connects",
  "severity": "high",
  "timestamp": 1790100022.0,
  "timestamp_iso": "2026-09-22T18:00:22+00:00",
  "src_ip": "198.51.100.88",
  "dst_ip": "192.0.2.20",
  "summary": "198.51.100.88 made 101 connection attempts to 192.0.2.20 within 5s",
  "evidence": {
    "connection_attempts": 101, "threshold": 100, "window_seconds": 5.0,
    "window_start": 1790100020.0, "window_end": 1790100022.0,
    "attempt_definition": "TCP SYN without ACK; first packet of a non-TCP flow"
  }
}
```

```json
{
  "rule_id": "RULE-005",
  "rule_name": "TCP SYN Flood Pattern",
  "severity": "high",
  "timestamp": 1790100030.49,
  "timestamp_iso": "2026-09-22T18:00:30.490000+00:00",
  "src_ip": null,
  "dst_ip": "192.0.2.30",
  "summary": "50/50 TCP packets to 192.0.2.30 are SYNs with no completed handshake (100%)",
  "evidence": {
    "syn_without_ack_packets": 50, "total_tcp_packets": 50, "syn_ratio": 1.0,
    "threshold_ratio": 0.8, "min_syn_packets": 50, "half_open_flows": 50,
    "established_flows": 0, "window_seconds": 10.0,
    "window_start": 1790100030.0, "window_end": 1790100030.49
  }
}
```

Summary of the demo run (`evidence/week2_detection_cli_output.txt`):

| Rule | Severity | Alert time (UTC) | Subject |
|---|---|---|---|
| RULE-001 | medium | 18:00:12 | 198.51.100.77 → 192.0.2.10, 21 unique ports |
| RULE-003 | high | 18:00:22 | 198.51.100.88 → 192.0.2.20, 101 attempts in 5 s |
| RULE-005 | high | 18:00:30.49 | → 192.0.2.30, 50/50 half-open SYNs |
| RULE-002 | medium | 18:01:38.35 | 192.0.2.40:51000 → 198.51.100.50:443, 10,494,054 bytes |
| RULE-004 | medium | 18:01:50 | 66-character query name |
| RULE-004 | medium | 18:01:51 | high-entropy label |

## 7. Test results

`pytest tests -v` → **169 passed, 1 skipped** (Linux, Python 3.12.3; the skipped test is the opt-in Week 1 live capture).

| Area | Tests | Covers |
|---|---|---|
| Flow engine | 55 | five-field key, counters, first/last seen, out-of-order packets, directionality, destination ports, flag/handshake tracking, ICMP, bad/missing fields |
| RULE-001 | 11 | positive, exactly 20 ports (no alert), 21st packet, window boundary at 10.0 s and just over, one host only, repeated ports, per source, cooldown |
| RULE-002 | 7 | positive, exactly 10 MB (no alert), per flow, per direction, once per flow, no timestamp, invalid lengths |
| RULE-003 | 10 | positive, exactly 100 (no alert), window boundary at 5.0 s and just over, ACKs/SYN-ACKs not counted, UDP, per destination |
| RULE-004 | 27 | positive (length, entropy, hex, digits), exactly 50 chars (no alert), trailing dot, 9 benign names, responses skipped, dedup, bad value types |
| RULE-005 | 13 | positive, completed handshakes, ratio exactly 0.80 and 0.802, minimum count, window, per destination, non-TCP, established-flow exclusion, minimum applies to half-open SYNs |
| Consistency / robustness / pipeline | 16 | rule ID, name and severity match the catalogue; identical alert keys; JSON-serialisable; repeatable; garbage input (None, NaN, wrong types) never crashes and never alerts; attack PCAP triggers all five rules; benign PCAP triggers none |

**Test quality check.** To verify the tests detect real bugs, I broke the code one change at a time (strict → non-strict comparisons, window edges, counting ACKs as attempts, ignoring established flows, removing the minimum-sample guard, swapping a severity). All of them made the suite fail, except one equivalent mutation (the cheap pre-check before the exact RULE-005 test, which cannot change the result).

**Issues found while testing**
1. Hex-only filler (`"a" * 38`) correctly triggered the hex-label pattern, so the RULE-004 boundary tests use a non-hex letter.
2. RULE-005 correctly alerted as soon as the half-open ratio crossed 0.8, so the boundary tests send diluting traffic first.
3. The first RULE-005 tests never exercised the "established flow" path (the exact count equalled the pre-check when no handshakes existed). Three tests with completed handshakes were added; mutation testing confirmed they catch the gap.
4. A scan of 100 ports also raises RULE-005 (see limitations); a test documents this on purpose.

**Performance.** 100,000 synthetic packets process in about 2 s (linear; sliding windows with O(1) updates).

## 8. Evidence

- `evidence/week2_pytest_output_linux.txt`: full `pytest -v` output (169 passed, 1 skipped)
- `evidence/week2_detection_cli_output.txt`: pipeline output on the attack and benign PCAPs
- `evidence/example_alerts.json`: all alert records
- Windows screenshot: *(add here)*

## 9. Known limitations

1. **Connection attempts are estimated.** TCP SYN-without-ACK counts as an attempt, so retransmitted SYNs are counted again. Non-TCP "attempts" are new 5-tuples, so a UDP/ICMP scan reusing one 5-tuple counts once. Attempts are per source and destination IP, so a distributed attack from many sources is not seen by RULE-003.
2. **SYN/ACK state is inferred, not tracked.** A flow is "established" when an ACK follows its SYN in the *same direction*; the server's SYN-ACK is deliberately ignored, because SYN floods also receive SYN-ACKs. Captures that only contain the server-to-client direction cannot show the final ACK, and the engine has no handshake timeout or sequence-number checks.
3. **RULE-001 and RULE-005 overlap.** A SYN scan with at least 50 SYNs and no handshakes matches both. The 50-packet minimum separates small scans only.
4. **RULE-005 is per destination host**, not per port, and uses a window and a minimum count that the assignment does not define.
5. **RULE-004 patterns are heuristics.** Letters-only random labels (no digits) and short labels are missed; long machine-generated hostnames with digits (for example CDN names) can false-alarm. The Week 1 record has no DNS record type or query/response flag, so responses are skipped by source port 53 only.
6. **Out-of-order timestamps.** `run_detection()` sorts by timestamp; the streaming `process()` API clamps backwards timestamps to the newest one seen.
7. **Records without a usable timestamp** update counters and can raise RULE-002 and RULE-004, but are ignored by the windowed rules.
8. **State is never expired.** Flow and window dictionaries grow with the number of distinct flows, and there is no flow timeout; this is fine for PCAP analysis but not for long-running live capture.
9. **Only vertical scans.** One source scanning many ports on one host is detected; one port across many hosts is not.
10. **Demo data is synthetic.** Thresholds were tested on controlled data only, not on real traffic, so false-positive rates are unknown.

## 10. How to run

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\make_attack_pcap.py
pytest tests -v
python -m backend.app.detection sample_pcaps\attack_demo.pcap
python -m backend.app.detection sample_pcaps\attack_demo.pcap --json
```