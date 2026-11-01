# PacketIQ AI

PacketIQ AI is a network packet analysis tool that I am building during the AeroVerix Security AI and Software Development internship. It reads packet captures, groups packets into flows, and raises alerts when traffic matches known attack patterns. The long-term goal is an AI layer that investigates those alerts automatically.

## Status

| Week | Area | Status |
|---|---|---|
| 1 | Packet capture and protocol parsing | Done |
| 2 | Flow aggregation and five detection rules | Done |
| 3 | Storage and API | Planned |
| 4 | Frontend, AI analysis and final integration | Planned |

## What works now

**Week 1: capture and parsing** (`backend/app/capture.py`)
- Lists network interfaces.
- Reads PCAP and PCAPNG files one packet at a time.
- Turns each packet into a fixed record with the same 13 fields: timestamp, length, source and destination IP, IP version, protocol, ports, TCP flags and DNS query. Fields that do not apply are `None`.
- Captures live traffic, but only with an explicit `--i-am-authorized` flag and a limit of 1000 packets or 60 seconds.

**Week 2: flows and detection** (`backend/app/flow_engine.py`, `backend/app/detection.py`)
- Groups packets into directional flows keyed by source IP, destination IP, source port, destination port and protocol.
- Tracks first and last seen times, packet and byte counts, destination ports, TCP flags, and whether a TCP handshake completed.
- Runs five detection rules and produces alerts with a rule ID, severity, evidence and timestamp.

| Rule | Name | Severity | Threshold |
|---|---|---|---|
| RULE-001 | Port Scan | medium | more than 20 unique destination ports on one host in 10 s |
| RULE-002 | Unusual Traffic Volume | medium | more than 10 MB in one flow |
| RULE-003 | High-Frequency Connects | high | more than 100 connection attempts to one destination in 5 s |
| RULE-004 | Suspicious DNS | medium | query longer than 50 characters, or a suspicious pattern |
| RULE-005 | TCP SYN Flood Pattern | high | SYN ratio above 80% without an established handshake |

All thresholds are in one place (`Thresholds` in `backend/app/detection.py`). Comparisons are strict, so a value exactly at a threshold does not alert.

## Project structure

```
packet-iq-ai/
├── backend/app/
│   ├── capture.py          Week 1: interfaces, PCAP reading, parsing, live capture
│   ├── flow_engine.py      Week 2: 5-tuple flow state
│   └── detection.py        Week 2: the five rules, alert records, detection CLI
├── tests/
│   ├── test_capture.py     Week 1 tests (31)
│   ├── test_flow_engine.py Week 2 flow tests (55)
│   ├── test_detection.py   Week 2 rule tests (84)
│   └── synth.py            helpers that build synthetic packet records
├── scripts/
│   ├── make_sample_pcap.py   creates sample_pcaps/sample.pcap
│   └── make_attack_pcap.py   creates sample_pcaps/attack_demo.pcap
├── sample_pcaps/
│   ├── sample.pcap         12 benign packets (documentation addresses)
│   └── attack_demo.pcap    synthetic traffic that triggers all five rules
├── evidence/               saved command output and example alerts
├── frontend/src/           placeholder for the Week 4 interface
├── REPORT.md               combined Week 1 and Week 2 report
├── requirements.txt
├── pytest.ini
└── .gitignore
```

## Requirements

- Python 3.10 or newer. I developed on Python 3.13.15 (Windows) and checked on 3.12.3 (Linux).
- The packages in `requirements.txt`.
- For live capture on Windows: Npcap (https://npcap.com), installed with the WinPcap-compatible option, and an Administrator PowerShell window.

## Setup

Windows (PowerShell):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the activation script, run this once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Linux or macOS:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running

Generate the sample files (they are deterministic, so the output never changes):

```powershell
python scripts\make_sample_pcap.py
python scripts\make_attack_pcap.py
```

Run the tests:

```powershell
pytest tests -v
```

Parse a capture (Week 1):

```powershell
python -m backend.app.capture parse sample_pcaps\sample.pcap
python -m backend.app.capture parse sample_pcaps\sample.pcap --json
python -m backend.app.capture interfaces
```

Run detection (Week 2):

```powershell
python -m backend.app.detection sample_pcaps\attack_demo.pcap
python -m backend.app.detection sample_pcaps\attack_demo.pcap --json
```

On Linux or macOS, replace `\` with `/`.

### Live capture (optional)

Only capture traffic on a network you own or are authorised to monitor.

```powershell
python -m backend.app.capture live Ethernet --count 10 --timeout 10 --i-am-authorized
```

Use the interface name from `python -m backend.app.capture interfaces`. The live test in pytest is skipped unless you set both of these first:

```powershell
$env:PACKETIQ_LIVE_TEST = "1"
$env:PACKETIQ_LIVE_IFACE = "Ethernet"
```

## Tests

| Suite | Count | Covers |
|---|---|---|
| `test_capture.py` | 31 | parsing, protocol labels, missing layers, file errors, live-capture guards |
| `test_flow_engine.py` | 55 | flow key, counters, timestamps, flags, bad input |
| `test_detection.py` | 84 | each rule's positive, negative and boundary cases, alert format, pipeline |

Expected result: `169 passed, 1 skipped` (the skipped test is the opt-in live capture).

## Design rules

- **Records are normalised before use.** Bad or missing values become `None`, so a malformed packet is counted and skipped instead of crashing the run.
- **Rules use packet time, not wall-clock time,** so the same file always gives the same alerts.
- **Each rule has one fixed severity,** so a rule ID always maps to the same severity.
- **Alerts are repeated at most once per cooldown,** so an ongoing scan does not flood the output.
- **Synthetic data only in the repository.** Sample captures use documentation addresses (RFC 5737, RFC 3849) and example.com. Real PCAP files are excluded by `.gitignore`.

## Known limitations

- Connection attempts are estimated from SYN packets, so retransmissions count again.
- Handshake state is inferred from an ACK after a SYN in the same direction. There are no timeouts or sequence-number checks.
- RULE-001 and RULE-005 both match a SYN scan of 50 or more ports.
- RULE-004 looks at DNS query names only. It can miss letters-only random names and can flag some long CDN hostnames.
- Flow state is kept in memory and never expires, which suits file analysis but not long live captures.
- The thresholds have only been tested on synthetic traffic.

Full details are in `REPORT.md`.

## Roadmap

**Week 3: storage and API**
- Save flows and alerts to a database with SQLAlchemy.
- Expose captures, flows and alerts through a FastAPI service.
- Add flow expiry so live capture can run for long periods.

**Week 4: interface and AI**
- Build a simple frontend in `frontend/src/` that lists alerts and flows.
- Add an AI layer that reads an alert with its evidence and writes an investigation summary.
- Load API keys from `.env` only. Never store them in code or in the repository.

**Later**
- Reduce false alerts for RULE-004 and RULE-005 using measured baselines.
- Track TCP sequence numbers for more accurate handshake state.
- Support multiple captures and a history view.

## Security

- The repository holds no API keys or passwords. Put local secrets in `.env`; Git ignores that file. `.env.example` is only a template.
- Use only traffic you own or have permission to test.
- Do not commit real PCAP files. `.gitignore` excludes them, except the two synthetic samples.
