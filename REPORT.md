# PacketIQ AI: Internship Report (Weeks 1 and 2)

**Name:** Nadji Houa
**Program:** AeroVerix Security, AI and Software Development Internship
**Week 1 due:** 27 October 2026
**Week 2 due:** 3 November 2026

## Contents

- Part A: Week 1, Packet Capture and Protocol Parsing
- Part B: Week 2, Flow Aggregation and Detection
- Part C: Project overview and how to run everything

---

# Part A: Week 1, Packet Capture and Protocol Parsing

## 1. What I was asked to do

The goal was to build the first part of PacketIQ AI. The program needs to find network interfaces, read saved PCAP files, and turn each packet into a set of standard fields: timestamp, length, source and destination IP, protocol, ports, TCP flags and DNS query. I also had to write tests that prove the parser works. Live capture was optional and only allowed on traffic I am authorised to monitor.

## 2. What I built

| Item | File |
|---|---|
| Capture module (interfaces, PCAP reading, parsing, live capture) | `backend/app/capture.py` |
| Synthetic sample capture (12 packets) | `sample_pcaps/sample.pcap` |
| Script that creates the sample | `scripts/make_sample_pcap.py` |
| Tests (31) | `tests/test_capture.py` |

The sample uses documentation IP ranges (192.0.2.x, 198.51.100.x, 203.0.113.x and 2001:db8::/32) and the domain example.com, so it contains no real traffic.

## 3. Environment

I ran Week 1 on Windows 11 with PowerShell.

- Python 3.13.15
- pytest 9.1.1
- Scapy 2.8.0

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\make_sample_pcap.py
pytest tests\test_capture.py -v
python -m backend.app.capture parse sample_pcaps\sample.pcap
```

## 4. How the code works

- **One record format.** Every packet becomes a `PacketRecord` with the same 13 fields. If a field does not exist for a packet (for example, ports on an ARP frame), it is `None`. The later parts of the project then do not need special cases for each protocol.
- **Protocol label.** I check the layers in this order: DNS, TCP, UDP, ICMP, ICMPv6, ARP, then OTHER. DNS is checked first because DNS runs over UDP, and I want it labelled as DNS.
- **Errors.** The parser does not stop on a bad packet. If something fails, that packet gets `protocol = OTHER` and a `parse_error` message, and the rest of the file is still read.
- **Missing layers.** ARP and raw Ethernet frames have no IP addresses. ICMP has no ports. An IPv4 packet with an unknown transport protocol keeps its IP addresses.
- **Length.** I use the on-wire length when the capture has it, and the captured length otherwise.
- **DNS.** I report the first question name, without the trailing dot. A DNS response repeats the question, so it shows the name too.
- **Reading files.** `iter_pcap` reads one packet at a time, so large files do not fill memory. `read_pcap` returns a list. A missing or invalid file raises `PcapReadError`.
- **Live capture.** The function refuses to run unless `authorized=True` is passed. The CLI needs `--i-am-authorized`. I capped it at 1000 packets and 60 seconds.

## 5. Week 1 test results

```
30 passed, 1 skipped in 0.51s
```

The skipped test is the live capture test. It only runs when `PACKETIQ_LIVE_TEST=1` and `PACKETIQ_LIVE_IFACE` are set.

Parsing the sample gave 12 packets:

```
  # proto    len src                          dst                          flags dns
  0 TCP       54 192.0.2.10:49152             198.51.100.20:80             S     -
  1 TCP       54 198.51.100.20:80             192.0.2.10:49152             SA    -
  2 TCP       91 192.0.2.10:49152             198.51.100.20:80             PA    -
  3 DNS       71 192.0.2.10:53000             192.0.2.53:53                -     example.com
  4 DNS       98 192.0.2.53:53                192.0.2.10:53000             -     example.com
  5 UDP       47 192.0.2.10:40000             203.0.113.5:9999             -     -
  6 ICMP      42 192.0.2.10                   198.51.100.20                -     -
  7 ARP       42 -                            -                            -     -
  8 TCP       74 2001:db8::1:50000            2001:db8::2:443              S     -
  9 ICMPv6    62 2001:db8::1                  2001:db8::2                  -     -
 10 OTHER     38 192.0.2.10                   198.51.100.20                -     -
 11 OTHER     18 -                            -                            -     -
```

## 6. Week 1 problems

1. **A test failed on the first run.** The test for an unknown interface expected a `CaptureError`, but Scapy raised a `ValueError`, which my code did not catch. I added `ValueError` to the caught exceptions and the test passed.
2. **Scapy warned that no libpcap provider was available.** Offline reading still works because Scapy uses its own reader. Live capture on Windows needs Npcap.
3. **Live capture failed without Npcap.** Scapy stopped with an error saying WinPcap is not installed. This is an environment problem, not a parsing problem. I have not yet tested live capture with Npcap installed.

## 7. Week 1 limitations

- I have not tested live capture on real traffic.
- The sample is synthetic, so it does not cover IP fragments, IPv6 extension headers, VLAN tags or tunnels.
- PCAPNG files are read by Scapy, but I did not test a PCAPNG sample.
- DNS: only the first question in a message is reported.
- Protocols are labelled from the layers Scapy decodes, not from port numbers. A DNS server on a non-standard port shows as UDP.
- I only tested on Windows.

---

# Part B: Week 2, Flow Aggregation and Detection

## 1. What I was asked to do

Week 1 turned packets into records. Week 2 uses those records to build flows, which are groups of packets that share the same five fields, and runs five detection rules on them. Each rule must produce an alert with a rule ID, a severity, the evidence that triggered it, and a timestamp. I also had to write tests for each rule, covering cases that should alert, cases that should not, and the threshold edges.

## 2. What I built

| Item | File |
|---|---|
| Flow engine | `backend/app/flow_engine.py` |
| Detection rules and alert records | `backend/app/detection.py` |
| Flow engine tests (55) | `tests/test_flow_engine.py` |
| Detection tests (84) | `tests/test_detection.py` |
| Helpers for building synthetic records | `tests/synth.py` |
| Synthetic attack capture (1,702 packets) | `sample_pcaps/attack_demo.pcap` |
| Script that creates the attack capture | `scripts/make_attack_pcap.py` |
| Example alert output | `evidence/example_alerts.json` |

The attack capture uses documentation IP addresses (RFC 5737) and no real traffic.

## 3. Flow state

A flow is identified by `(src_ip, dst_ip, src_port, dst_port, protocol)`. Flows have a direction, so A to B and B to A are two different flows. For each flow I track:

- `first_seen` and `last_seen`, using the smallest and largest valid timestamp, so out-of-order packets do not break them
- `packet_count` and `byte_count`
- the destination port
- counts of each TCP flag
- the number of SYN packets without ACK (connection attempts)
- whether the flow completed a handshake. A flow counts as established only when an ACK follows a SYN from the same direction.

I also keep, for each source and destination host, the set of destination ports used. The port-scan rule needs this.

Input is checked before use. A missing or invalid value becomes `None`, and a missing length becomes 0. A record with no valid source IP, destination IP or protocol cannot form a flow, so I count it in the engine's stats instead of raising an error.

## 4. The five rules and thresholds

I used the thresholds from the assignment. Every comparison is strict (`>`), so a value exactly on the threshold does not alert.

| Rule | Name | Severity | Threshold |
|---|---|---|---|
| RULE-001 | Port Scan | medium | more than 20 unique destination ports on one host within 10 s |
| RULE-002 | Unusual Traffic Volume | medium | more than 10 MB in one flow |
| RULE-003 | High-Frequency Connects | high | more than 100 connection attempts to one destination within 5 s |
| RULE-004 | Suspicious DNS | medium | query longer than 50 characters, or a suspicious pattern |
| RULE-005 | TCP SYN Flood Pattern | high | SYN ratio above 80% without established ACK state |

The assignment did not give some values, so I chose them. They are all in one place (`Thresholds` in `detection.py`):

- **10 MB** is 10 × 1024 × 1024 bytes. If the handbook means 10,000,000 bytes, change `volume_bytes`.
- **Severities.** The assignment did not specify them. I set RULE-003 and RULE-005 to high and the others to medium.
- **RULE-005 window and minimum.** The ratio is measured over 10 seconds, and the rule only fires with at least 50 half-open SYN packets. Without that minimum, one SYN with no reply would give 100%.
- **RULE-004 "suspicious pattern".** The assignment did not define it, so I used three checks: a label of 16 or more characters with both letters and digits and an entropy of at least 3.5 bits per character; a hex-only label of 32 or more characters; and a label of 12 or more characters that is at least 60% digits.
- **Repeat alerts.** The same rule on the same key alerts at most once every 60 seconds. RULE-002 alerts once per flow. RULE-004 alerts once per source and query name.

Window edges are inclusive: an event stays in a 10-second window while the time since it is 10 seconds or less.

## 5. How each rule works

- **RULE-001** counts unique destination ports per source and destination host in a sliding 10-second window.
- **RULE-002** checks each flow's byte count. It does not add traffic across flows or between the two directions.
- **RULE-003** counts connection attempts per source and destination IP in a sliding 5-second window. A TCP SYN without ACK counts as one attempt, and so does the first packet of a new UDP or other non-TCP flow. Plain ACKs and SYN-ACKs do not count.
- **RULE-004** checks DNS queries only. I skip packets from source port 53, because those are responses and repeat the question. I convert the name to lower case and remove the trailing dot before measuring it.
- **RULE-005** looks at TCP packets sent to one host in a 10-second window. A SYN counts as half-open if its flow never completed a handshake. The rule fires when half-open SYNs are more than 80% of all TCP packets to that host and there are at least 50 of them.

## 6. Pipeline

1. `read_pcap()` from Week 1 gives a list of records.
2. `run_detection()` sorts them by timestamp.
3. For each record, the flow engine updates its flow, then the five rules run.

```powershell
python -m backend.app.detection sample_pcaps\attack_demo.pcap
python -m backend.app.detection sample_pcaps\attack_demo.pcap --json
```

## 7. Attack capture and results

`scripts/make_attack_pcap.py` creates a capture with one scenario per rule, plus normal traffic:

- a port scan from 198.51.100.77 to 192.0.2.10 (RULE-001)
- a large flow of about 10.5 MB (RULE-002)
- 130 connections to 192.0.2.20 in a few seconds (RULE-003)
- 200 SYNs from different sources to 192.0.2.30 (RULE-005)
- two suspicious DNS queries, one long and one with a random-looking label (RULE-004)
- two normal TCP handshakes and a normal DNS lookup, which should not alert

Running detection on this file gave six alerts: one each for RULE-001, RULE-002, RULE-003 and RULE-005, and two for RULE-004. Each alert pointed at the host I expected. The Week 1 sample gave zero alerts.

The large flow is stored with headers only, but each record keeps its original 9,000-byte size. That keeps the file at about 119 KB instead of 10 MB.

Example alert for RULE-003:

```json
{
  "rule_id": "RULE-003",
  "rule_name": "High-Frequency Connects",
  "severity": "high",
  "timestamp_iso": "2026-09-22T18:00:22+00:00",
  "src_ip": "198.51.100.88",
  "dst_ip": "192.0.2.20",
  "summary": "198.51.100.88 made 101 connection attempts to 192.0.2.20 within 5s",
  "evidence": {
    "connection_attempts": 101,
    "threshold": 100,
    "window_seconds": 5.0,
    "window_start": 1790100020.0,
    "window_end": 1790100022.0
  }
}
```

The full alert list is in `evidence/example_alerts.json`.

## 8. Week 2 tests

On Linux with Python 3.12.3 I ran `pytest tests -v` and got **169 passed, 1 skipped**. The skipped test is the Week 1 live capture test.

**Windows run:** *(paste your `pytest tests -v` result here before submitting)*

| File | Tests | What they check |
|---|---|---|
| `test_flow_engine.py` | 55 | the five-field key, counters, timestamps, direction, ports, TCP flags, bad input |
| `test_detection.py` | 84 | each rule's positive, negative and threshold-edge cases, alert format, repeatability, bad input, and two pipeline runs |

For each threshold rule I tested the exact boundary: exactly 20 ports, exactly 100 attempts, exactly 10 MB, exactly 50 characters, and exactly 80%. The boundary value must not alert, and one more must.

To check the tests catch real bugs, I changed the code on purpose, one change at a time: a `>` to `>=`, a window made exclusive, ACKs counted as attempts, established flows ignored, the minimum count removed, and a severity swapped. The suite failed for each change. The one change it did not catch was an extra check before the RULE-005 calculation, which cannot change the result.

Writing the tests exposed problems, which I fixed:

- A run of repeated `a` characters is a valid hex string and tripped the hex rule, so the boundary tests use `q`.
- RULE-005 alerts as soon as the ratio passes 80%, so the boundary tests send the normal traffic first.
- My first RULE-005 tests never reached the "established flow" code. I added tests with completed handshakes.

## 9. Week 2 limitations

1. **Connection attempts are estimates.** Each SYN counts, so retransmissions count again. A non-TCP scan that reuses one 5-tuple counts once. RULE-003 groups attempts by source and destination IP, so a distributed attack from many sources is not detected.
2. **Handshake state is inferred.** A flow counts as established when an ACK follows a SYN in the same direction. I ignore the server's SYN-ACK, because a SYN flood also gets SYN-ACKs. If a capture has only one direction, the final ACK may be missing. There are no timeouts or sequence-number checks.
3. **RULE-001 and RULE-005 overlap.** A SYN scan that sends at least 50 SYNs with no handshakes matches both. The minimum of 50 is the only thing that separates a small scan from a flood.
4. **RULE-005 is per host, not per port.** The 10-second window and the minimum of 50 are my own choices.
5. **RULE-004 misses some cases.** Random letters-only labels are not caught, and long machine-generated names with digits, such as CDN hostnames, could trigger a false alert. The Week 1 record has no DNS query-type field, so responses are identified only by source port 53.
6. **Late timestamps.** `run_detection()` sorts by time first. The streaming `process()` method sets a backwards timestamp to the latest time seen.
7. **Packets without a timestamp** still update counters and can trigger RULE-002 and RULE-004, but the time-window rules ignore them.
8. **Nothing expires.** Flow and window data grows with the number of flows, and there is no flow timeout. This is fine for reading a file, but a long live capture would use more memory over time.
9. **Vertical scans only.** A port scan of one host is detected. The same port scanned across many hosts is not.
10. **Thresholds are tested only on synthetic data.** I do not know how often they would give false alarms on real traffic.

## 10. Week 2 summary

The flow engine groups packets into five-field flows and keeps the counters and times the assignment asks for. All five rules run, and each has a positive test, a negative test and boundary tests. On the synthetic attack capture, each rule alerted on the host I designed it to catch. The normal traffic and the Week 1 sample alerted on nothing. The main weaknesses are the estimated connection attempts and handshake state, and the overlap between RULE-001 and RULE-005.

---

# Part C: Project overview and how to run everything

## 1- Layout

```
packet-iq-ai/
├── backend/app/capture.py        Week 1: capture, parsing, live capture
├── backend/app/flow_engine.py    Week 2: flow state
├── backend/app/detection.py      Week 2: five rules and alert records
├── tests/                        Week 1 and Week 2 tests
├── scripts/                      generators for the two sample captures
├── sample_pcaps/                 sample.pcap and attack_demo.pcap
├── evidence/                     command output and example alerts
├── frontend/src/                 placeholder for Week 4
├── REPORT.md                     this report
├── README.md
└── requirements.txt
```

## 2- Full run sequence (Windows)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts\make_sample_pcap.py
python scripts\make_attack_pcap.py
pytest tests -v
python -m backend.app.capture parse sample_pcaps\sample.pcap
python -m backend.app.detection sample_pcaps\attack_demo.pcap
```

Expected: 169 passed and 1 skipped, the Week 1 parse table, and six alerts from the detection run.

## 3- Live capture

Live capture is optional and only allowed on a network I own or am authorised to monitor. It requires Npcap on Windows and an explicit flag:

```powershell
python -m backend.app.capture live Ethernet --count 10 --timeout 10 --i-am-authorized
```

## 4- Known gaps across both weeks

- Live capture has not been tested on real traffic.
- Week 2 has been run on Linux only; the Windows run is pending.
- Thresholds have only been tested on synthetic traffic.
- Flow state is in memory with no expiry.
