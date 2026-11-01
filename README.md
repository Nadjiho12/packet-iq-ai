# PacketIQ AI: Packet Capture & Protocol Parsing (Week 1)

Foundation layer of PacketIQ AI: discover capture interfaces, read PCAP files offline, and parse packets into a fixed, protocol-independent record format. Built for the AeroVerix Security AI & Software Development internship.

## Project structure

```
packet-iq-ai/
├── backend/app/capture.py      # Week 1: interface discovery, PCAP reading, packet parsing, guarded live capture
├── backend/app/flow_engine.py  # Week 2: 5-tuple flow aggregation
├── backend/app/detection.py    # Week 2: five detection rules (RULE-001..005) + alert records
├── frontend/src/               # placeholder for later weeks
├── sample_pcaps/sample.pcap    # Week 1: 12 synthetic packets (documentation addresses only)
├── sample_pcaps/attack_demo.pcap # Week 2: synthetic traffic that triggers all five rules
├── scripts/make_sample_pcap.py # regenerates sample.pcap deterministically
├── scripts/make_attack_pcap.py # regenerates attack_demo.pcap deterministically
├── tests/test_capture.py       # Week 1: 31 tests
├── tests/test_flow_engine.py   # Week 2: 55 tests
├── tests/test_detection.py     # Week 2: 84 tests
├── tests/synth.py              # synthetic record builders for the tests
├── evidence/                   # saved test and CLI output
├── requirements.txt
├── pytest.ini
├── .env.example                # placeholders only; never commit real secrets
└── .gitignore                  # excludes venv, .env, and all PCAPs except the two synthetic samples
```

## Requirements

- Python 3.12 or 3.13 (tested with Python 3.13.15 on Windows and 3.12.3 on Linux)
- Packages in `requirements.txt` (Scapy 2.8.0, pytest 9.1.1, plus FastAPI, Uvicorn, SQLAlchemy, Pydantic, python-dotenv, requests as required by the handbook)
- Optional, for live capture only: Npcap on Windows (https://npcap.com) or libpcap on Linux/macOS, and root/Administrator privileges

## Setup (Windows PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the activation script, run once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Command Prompt users: `venv\Scripts\activate.bat`

## Setup (Linux / macOS)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

```powershell
python scripts\make_sample_pcap.py
pytest tests\test_capture.py -v
python -m backend.app.capture parse sample_pcaps\sample.pcap
python -m backend.app.capture parse sample_pcaps\sample.pcap --json
python -m backend.app.capture interfaces
```

(On Linux/macOS, replace `\` with `/`.)
## Live capture (optional, authorized use only)

Only capture traffic on an interface you own or are permitted to monitor. Live capture is capped at 1000 packets and 60 seconds, and requires an explicit confirmation flag:

```powershell
python -m backend.app.capture live <interface> --count 10 --timeout 10 --i-am-authorized
```

The opt-in pytest live test runs only when you set `PACKETIQ_LIVE_TEST=1` and `PACKETIQ_LIVE_IFACE=<interface>`.

## Week 2: flow aggregation and detection

```powershell
python scripts\make_attack_pcap.py
pytest tests -v                             # 169 passed, 1 skipped (Linux)
python -m backend.app.detection sample_pcaps\attack_demo.pcap       # alert table
python -m backend.app.detection sample_pcaps\attack_demo.pcap --json
```

| Rule | Name | Severity | Threshold |
|---|---|---|---|
| RULE-001 | Port Scan | medium | > 20 unique destination ports on one host in 10 s |
| RULE-002 | Unusual Traffic Volume | medium | > 10 MB in one flow |
| RULE-003 | High-Frequency Connects | high | > 100 connection attempts to one destination in 5 s |
| RULE-004 | Suspicious DNS | medium | query length > 50 characters, or suspicious pattern |
| RULE-005 | TCP SYN Flood Pattern | high | SYN ratio > 80% without established ACK state |
