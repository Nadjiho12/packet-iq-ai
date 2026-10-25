# README

# PacketIQ AI: Packet Capture & Protocol Parsing (Week 1)

Foundation layer of PacketIQ AI: discover capture interfaces, read PCAP files offline, and parse packets into a fixed, protocol-independent record format. Built for the AeroVerix Security AI & Software Development internship.

## Project structure

```
packet-iq-ai/
├── backend/app/capture.py      # interface discovery, PCAP reading, packet parsing, guarded live capture
├── frontend/src/               # placeholder for later weeks
├── sample_pcaps/sample.pcap    # 12 synthetic packets (documentation addresses only)
├── scripts/make_sample_pcap.py # regenerates the sample deterministically
├── tests/test_capture.py       # 31 tests
├── evidence/                   # saved test and CLI output
├── requirements.txt
├── pytest.ini
└── .gitignore                  # excludes venv, .env, and all PCAPs except the sample
```

## Requirements

- Python 3.10 or newer (tested with Python 3.13.15 on Windows and 3.12.3 on Linux)
- Packages in `requirements.txt` (Scapy 2.8.0, pytest 9.1.1, plus FastAPI, Uvicorn, SQLAlchemy, Pydantic, python-dotenv, requests as required by the handbook)
- Optional, for live capture only: Npcap on Windows ([https://npcap.com](https://npcap.com/)) or libpcap on Linux/macOS, and root/Administrator privileges

## Setup (Windows PowerShell)

```powershell
> python -m venv venv

> .\venv\Scripts\Activate.ps1

> pip install -r requirements.txt
```

If PowerShell blocks the activation script, run once:

```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Command Prompt users: `venv\Scripts\activate.bat`

## Setup (Linux / macOS)

```bash
$ python3 -m venv venv

$ source venv/bin/activate

$ pip install -r requirements.txt
```

## Run

```powershell
> python scripts\make_sample_pcap.py

> pytest tests\test_capture.py -v

> python -m backend.app.capture parse sample_pcaps\sample.pcap

> python -m backend.app.capture parse sample_pcaps\sample.pcap --json

> python -m backend.app.capture interfaces
```

(On Linux/macOS, replace `\` with `/`.)

## Live capture (optional, authorized use only)

Only capture traffic on an interface you own or are permitted to monitor. Live capture is capped at 1000 packets and 60 seconds, and requires an explicit confirmation flag:

```powershell
> python -m backend.app.capture live <interface> --count 10 --timeout 10 --i-am-authorized
```

The opt-in pytest live test runs only when you set `PACKETIQ_LIVE_TEST=1` and `PACKETIQ_LIVE_IFACE=<interface>`.

## Expected results

`pytest tests\test_capture.py -v` → **30 passed, 1 skipped** (the skipped test is the opt-in live capture).