# PacketIQ AI: Combined Report, Weeks 2 and 3

**Program:** AeroVerix Security, PacketIQ AI Technical Internship
**Author:** Nadji12
**Week 2:** Flow Aggregation & Detection Engine (assigned 29 Oct 2026, deadline 3 Nov 2026, 11:59 PM PKT)
**Week 3:** AI Investigation Agent & Automated Alerting (assigned 5 Nov 2026, deadline 10 Nov 2026, 11:59 PM PKT)

## Overview

PacketIQ AI turns network packet captures into explained security alerts. In Week 1 I built the capture and parsing layer. In Week 2 I added stateful flows and five detection rules. In Week 3 I added an AI investigation step and email notification on top of those alerts.

```
PCAP -> capture.py -> PacketRecord -> flow_engine.py -> detection.py -> Alert (RULE-001..005)
                                                                          |
                                                    ai_agent.py  -> ThreatReport (validated JSON)
                                                                          |
                                                    notifier.py  -> SMTP email (STARTTLS)
                                    (pipeline.py connects all steps; AI and email are opt-in)
```

| Week | Module | Tests |
|---|---|---|
| 1 | `capture.py` | 31 (1 opt-in live test skipped) |
| 2 | `flow_engine.py`, `detection.py` | 139 |
| 3 | `ai_agent.py`, `notifier.py`, `pipeline.py` | 29 |

Overall: **198 passed, 1 skipped** (Linux, Python 3.12.3).

---

# Part A: Week 2, Flow Aggregation & Detection Engine

### 1- Objective

Turn parsed packets (the Week 1 `PacketRecord` format) into stateful 5-tuple flows, and implement the five heuristic detection rules (RULE-001 to RULE-005) with consistent alert objects.

### 2- Deliverables

| Deliverable | Location |
|---|---|
| Flow engine | `backend/app/flow_engine.py` |
| Detection engine (5 rules) | `backend/app/detection.py` |
| Unit tests | `tests/test_flow_engine.py` (55), `tests/test_detection.py` (84) |
| Shared synthetic-data helpers | `tests/synth.py` |
| Synthetic attack PCAP + generator | `sample_pcaps/attack_demo.pcap`, `scripts/make_attack_pcap.py` |
| Example alert records | `evidence/example_alerts.json` (section 6) |
| Test and CLI output | `evidence/week2_pytest_output_linux.txt`, `evidence/week2_detection_cli_output.txt` |

### 3- Flow state (`flow_engine.py`)

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

### 4- Detection rules (`detection.py`)

All comparisons are strict (`>`): a value exactly at a threshold does **not** alert. All values are in one `Thresholds` dataclass.

#### 1. Thresholds

| Rule | Name | Severity | Threshold (from the assignment) |
|---|---|---|---|
| RULE-001 | Port Scan | medium | > 20 unique destination ports on one host within 10 s |
| RULE-002 | Unusual Traffic Volume | medium | > 10 MB in one flow |
| RULE-003 | High-Frequency Connects | high | > 100 connection attempts to one destination within 5 s |
| RULE-004 | Suspicious DNS | medium | query length > 50 characters, or suspicious pattern |
| RULE-005 | TCP SYN Flood Pattern | high | SYN ratio > 80% without corresponding established ACK state |

Each rule has one fixed severity so rule ID and severity are always consistent (tested).

#### 2. Assumptions and prototype parameters (not specified in the assignment)

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

#### 3. How each rule works

- **RULE-001.** Per (src, dst): a sliding 10 s window of destination ports with an O(1) unique count. Alerts when unique > 20.
- **RULE-002.** Per directional flow: alerts when `byte_count` > threshold, once per flow. A flow's bytes are not pooled with other flows or with the reverse direction.
- **RULE-003.** Per (src, dst IP): counts *connection attempts* in a sliding 5 s window. An attempt is a TCP packet with SYN and no ACK, or the first packet of a non-TCP flow. Plain ACKs and SYN-ACKs do not count.
- **RULE-004.** Evaluates DNS queries only. Packets from source port 53 are treated as responses and skipped, because a response repeats the question. Query names are lower-cased and the trailing dot is removed before measuring length.
- **RULE-005.** Per destination host, over TCP packets in a 10 s window. A SYN counts as *half-open* if its flow never completed a handshake (`ack_after_syn` false). Alert when `half-open SYNs / all TCP packets to that host > 0.8` and half-open SYNs ≥ 50. Completed handshakes therefore both leave the numerator and add their ACK packets to the denominator.

### 5- Pipeline (task 4)

`capture.read_pcap()` → `PacketRecord` list → `run_detection()` (sorts by timestamp) → `DetectionEngine.process()` for each record: `FlowEngine.update()` then the five rules. Command line:

```
python -m backend.app.detection sample_pcaps/attack_demo.pcap          # table
python -m backend.app.detection sample_pcaps/attack_demo.pcap --json   # alert records
```

`attack_demo.pcap` (1,702 synthetic packets, RFC 5737 addresses) contains one scenario per rule plus benign handshakes and a DNS lookup. Result: exactly one alert for RULE-001, -002, -003, -005 and two for RULE-004, each attributed to the intended host, and **zero alerts** on the benign Week 1 `sample.pcap`. The RULE-002 flow is a header-only (snaplen-truncated) capture whose records keep their original wire length (9000 bytes), so the file is 119 KB instead of 10 MB.

### 6- Example alert records

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

### 7- Test results

`pytest tests -v` → **169 passed, 1 skipped at the end of Week 2** (Linux, Python 3.12.3; the skipped test is the opt-in Week 1 live capture).

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

### 8- Known limitations (Week 2)

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

---

# Part B: Week 3, AI Investigation Agent & Automated Alerting

### 1- What I built

For every alert from the Week 2 detection engine, I generate an AI investigation report that is validated against a Pydantic schema, and I can send it by email. The original alert is never lost or changed, even when the AI or the email step fails.

| Deliverable | Location |
|---|---|
| AI agent and Pydantic schema | `backend/app/ai_agent.py` |
| Email notifier | `backend/app/notifier.py` |
| Pipeline and CLI (detection, then AI, then email) | `backend/app/pipeline.py` |
| Tests | `tests/test_ai_agent.py` (17), `tests/test_notifier.py` (4), `tests/test_pipeline.py` (8) |
| Sample validated JSON | `evidence/week3_sample_report.json` |
| Mocked email and data-minimization evidence | `evidence/week3_mock_email_evidence.txt` |
| Failure-path evidence | `evidence/week3_failure_demo.txt` |
| Full test output | `evidence/week3_pytest_output_linux.txt` |
| Env template | `.env.example` (placeholders only) |

### 2- ThreatReport schema

| Field | Type | Validation |
|---|---|---|
| `summary` | string | non-empty |
| `observed_behavior` | string | non-empty |
| `severity_recommendation` | string | lower-cased; one of low, medium, high, critical |
| `confidence_score` | float | 0.0 to 1.0 inclusive |
| `benign_explanations` | list of strings | required |
| `next_steps` | list of strings | required |

`investigate_alert(alert)` returns `{alert, report, investigation_status, investigation_error}`. `alert` is the original object, unmodified. `investigation_status` is `ok`, `failed` or `skipped`.

### 3- Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `AI_API_KEY` | provider key (required for AI) | none |
| `AI_API_URL` | OpenAI-compatible chat-completions endpoint | OpenAI URL |
| `AI_MODEL` | model name | `gpt-4o-mini` |
| `AI_TIMEOUT_SEC` | request timeout in seconds | 20 |
| `SMTP_HOST`, `SMTP_PORT` | mail server | port 587 |
| `SMTP_USER`, `SMTP_PASSWORD` | SMTP login | none |
| `SMTP_FROM`, `ALERT_EMAIL_TO` | sender and recipient | `SMTP_USER`, none |

I read secrets only from the environment (or a git-ignored `.env`). If the SMTP settings are incomplete, the notification is skipped.

### 4- Data minimization

I send the provider only allow-listed fields: rule ID and name, severity, ISO timestamp, source and destination IP, and numeric or short evidence values (port counts, attempt counts, SYN ratio, byte counts, flow 5-tuple, DNS reason codes and query length).

I never send PCAP files, packet payloads, credentials, the alert `summary` text, or the DNS query name. RULE-004 summaries contain the queried domain, which can reveal browsing, so I leave it out. The exact request body is in `evidence/week3_mock_email_evidence.txt`.

### 5- Error handling

| Failure | Behavior |
|---|---|
| Missing API key | `AIConfigError`, contained |
| Timeout | `AITimeoutError`, contained |
| Network error or HTTP status other than 200 | `AIProviderError` (status code or exception type only) |
| Missing or empty response content | `AIProviderError` |
| Invalid JSON (markdown code fences are tolerated) | `AIInvalidJSONError` |
| Schema violation or `confidence_score` out of range | `AISchemaError` (field names only) |
| Anything unexpected, including a non-dict alert | caught; exception type only |

In every case the pipeline keeps running, the original alert is preserved, and the email (if enabled) still goes out with the original alert and the failure reason. Error strings and logs contain no API key, no SMTP password and no raw exception text that could echo them. `--max-alerts` (default 20) caps AI calls per run to control cost.

### 6- Notifier

The notifier uses SMTP with `starttls()` and the default SSL context, then logs in and sends, with a 15 s timeout. It returns True or False and never raises. The subject is `[PacketIQ][SEVERITY] RULE-ID detected`. The body has the detection summary and, when available, the AI summary, observed behavior, recommended severity and confidence, benign explanations and next steps.

### 7- Tests

| File | Tests | Covers |
|---|---|---|
| `test_ai_agent.py` | 17 | valid output, fenced JSON, malformed JSON, confidence bounds, missing field, timeout, HTTP 500, empty content, missing key, minimal data, DNS name not sent, non-dict alert, no secrets in logs or errors |
| `test_notifier.py` | 4 | STARTTLS then login then send, email after a failed investigation, skipped without config, SMTP error contained with no password logged |
| `test_pipeline.py` | 8 | all six attack-demo alerts enriched, no DNS names sent, provider down keeps every alert, AI disabled makes no calls, `--max-alerts` cap, email failure does not affect the result, CLI output, missing file |

The provider and SMTP are mocked in every test, so they need no network or credentials.

### 8- Evidence

- `evidence/week3_pytest_output_linux.txt`: full run, 198 passed, 1 skipped
- `evidence/week3_mock_email_evidence.txt`: minimized request, validated report, mocked SMTP sequence and message (credentials redacted)
- `evidence/week3_failure_demo.txt`: timeout handled, alert preserved

### 9- Limitations (Week 3)

1. It supports OpenAI-compatible chat-completions endpoints only.
2. The AI report is advisory. `confidence_score` is reported by the model, not calibrated.
3. Internal IPs and port lists are sent to the provider.
4. Leaving out DNS query names protects privacy but gives the model less context on RULE-004 alerts.
5. There is no retry or backoff, and calls and emails are sent one after another.
6. It sends one email per alert, with no batching or throttling.
7. The automated tests mock the provider and SMTP, so they do not exercise real delivery.

---

# Combined evidence

| Item | File |
|---|---|
| Week 1 parsing output | `evidence/cli_parse_output.txt`, `evidence/pytest_output_linux.txt`, `evidence/windows_run_output.txt`, `evidence/wireshark.png` |
| Week 2 detection | `evidence/week2_pytest_output_linux.txt`, `evidence/week2_detection_cli_output.txt`, `evidence/example_alerts.json` |
| Week 3 AI and alerting | `evidence/week3_*` (see B8) |

# How to run

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\make_attack_pcap.py
pytest tests -v
python -m backend.app.detection sample_pcaps\attack_demo.pcap
python -m evidence.week3_mock_demo
python -m backend.app.pipeline sample_pcaps\attack_demo.pcap --ai --email
```
