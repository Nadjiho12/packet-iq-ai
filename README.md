# PacketIQ AI

AI-powered network packet analysis and autonomous threat investigation, built for the AeroVerix Security AI & Software Development internship.

This project reads packet captures, groups packets into flows and applies five detection rules. It can then ask an AI provider for a structured investigation report on each alert and send the result by email.

```
PCAP -> capture.py -> flow_engine.py -> detection.py -> alerts
                                                          |
                              ai_agent.py (ThreatReport) -> notifier.py (SMTP)
                                  pipeline.py connects the steps
```

## What I built

| Week | Focus | Modules |
|---|---|---|
| 1 | Packet capture and protocol parsing | `capture.py` |
| 2 | Flow aggregation and detection engine | `flow_engine.py`, `detection.py` |
| 3 | AI investigation agent and automated alerting | `ai_agent.py`, `notifier.py`, `pipeline.py` |

The test suite has 198 passing tests and 1 skipped (the opt-in live capture). The full write-up is in [REPORT.md](REPORT.md).

## Project structure

```
packet-iq-ai/
├── backend/app/
│   ├── capture.py        # W1: interface discovery, PCAP reading, packet parsing, guarded live capture
│   ├── flow_engine.py    # W2: 5-tuple flow aggregation
│   ├── detection.py      # W2: RULE-001..005 + alert records
│   ├── ai_agent.py       # W3: ThreatReport schema, provider call, validation, safe failure
│   ├── notifier.py       # W3: SMTP + STARTTLS email
│   └── pipeline.py       # W3: detection -> AI -> email, CLI
├── frontend/src/         # placeholder for later weeks
├── sample_pcaps/         # sample.pcap (benign), attack_demo.pcap (triggers all five rules); synthetic only
├── scripts/              # deterministic PCAP generators
├── tests/                # capture, flow engine, detection, ai_agent, notifier, pipeline
├── evidence/             # saved test output, alerts, mocked email evidence
├── .env.example          # placeholders only; never commit real secrets
├── requirements.txt
└── pytest.ini
```

## Setup

Python 3.12 or 3.13. Live capture also needs Npcap on Windows or libpcap on Linux/macOS, plus administrator rights.

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If activation is blocked, run once: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

Linux / macOS:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

Parse a capture (Week 1):

```powershell
python -m backend.app.capture parse sample_pcaps\sample.pcap
python -m backend.app.capture interfaces
```

Detect (Weeks 1-2):

```powershell
python scripts\make_attack_pcap.py
python -m backend.app.detection sample_pcaps\attack_demo.pcap          # alert table
python -m backend.app.detection sample_pcaps\attack_demo.pcap --json
```

AI investigation and email (Week 3). Copy `.env.example` to `.env` and fill it in, or set the variables in your shell:

```powershell
python -m backend.app.pipeline sample_pcaps\attack_demo.pcap                 # detection only
python -m backend.app.pipeline sample_pcaps\attack_demo.pcap --ai            # + AI reports
python -m backend.app.pipeline sample_pcaps\attack_demo.pcap --ai --email    # + email per alert
python -m backend.app.pipeline sample_pcaps\attack_demo.pcap --ai --max-alerts 5 --json
```

Mocked end-to-end demo (no credentials needed): `python -m evidence.week3_mock_demo`

Tests (no network or credentials needed, provider and SMTP are mocked):

```powershell
pytest tests -v
```

On Linux/macOS replace `\` with `/`.

## Detection rules

| Rule | Name | Severity | Threshold |
|---|---|---|---|
| RULE-001 | Port Scan | medium | > 20 unique destination ports on one host in 10 s |
| RULE-002 | Unusual Traffic Volume | medium | > 10 MB in one flow |
| RULE-003 | High-Frequency Connects | high | > 100 connection attempts to one destination in 5 s |
| RULE-004 | Suspicious DNS | medium | query length > 50 characters, or suspicious pattern |
| RULE-005 | TCP SYN Flood Pattern | high | SYN ratio > 80% without established ACK state |

## Configuration (environment variables)

| Variable | Purpose | Default |
|---|---|---|
| `AI_API_KEY` | provider key, required for `--ai` | none |
| `AI_API_URL` | OpenAI-compatible chat-completions endpoint | OpenAI URL |
| `AI_MODEL` | model name | `gpt-4o-mini` |
| `AI_TIMEOUT_SEC` | request timeout | 20 |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` | mail server (STARTTLS) | port 587 |
| `SMTP_FROM`, `ALERT_EMAIL_TO` | sender and recipient | `SMTP_USER`, none |

## Safety and privacy

- Live capture is capped at 1000 packets and 60 seconds. Run it only on traffic you are permitted to capture.
- The AI provider receives only allow-listed alert metadata. Packets, payloads, credentials, alert summary text and DNS query names are never sent.
- AI or email failures never drop or alter a detection alert.
- API keys and SMTP passwords are read from the environment only and never logged. `.env` and real PCAPs are git-ignored; only the two synthetic sample PCAPs are tracked.
