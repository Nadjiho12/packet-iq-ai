# PacketIQ AI: Packet Capture and Protocol Parsing (Week 1)

This is my Week 1 project for the AeroVerix internship. It finds network interfaces, reads saved PCAP files, and turns each packet into a fixed set of fields that the later parts of PacketIQ AI will use.

## Folder structure

```
packet-iq-ai/
├── backend/app/capture.py       capture module
├── frontend/src/                placeholder for later weeks
├── sample_pcaps/sample.pcap     12 synthetic packets, no real traffic
├── scripts/make_sample_pcap.py  creates the sample file
├── tests/test_capture.py        31 tests
├── evidence/                    test output and screenshots
├── requirements.txt
├── pytest.ini
├── .env.example                 template for local settings
└── .gitignore
```

## What you need

- Python 3.10 or newer. I used Python 3.13.15 on Windows.
- The packages in `requirements.txt`.
- For live capture only: Npcap on Windows (https://npcap.com), and Administrator rights.

## Setup on Windows (PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell blocks the activation script, run this once and try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

In Command Prompt, use `venv\Scripts\activate.bat` instead.

## Setup on Linux or macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running it

```powershell
python scripts\make_sample_pcap.py
pytest tests\test_capture.py -v
python -m backend.app.capture parse sample_pcaps\sample.pcap
python -m backend.app.capture parse sample_pcaps\sample.pcap --json
python -m backend.app.capture interfaces
```

On Linux or macOS, replace `\` with `/`.

## Live capture (optional)

Only capture traffic on a network you own or have permission to monitor. Live capture is limited to 1000 packets and 60 seconds, and needs the confirmation flag:

```powershell
python -m backend.app.capture live Ethernet --count 10 --timeout 10 --i-am-authorized
```

Replace `Ethernet` with the name of your interface from the `interfaces` command.

The live test in pytest is skipped by default. To run it, set these first:

```powershell
$env:PACKETIQ_LIVE_TEST = "1"
$env:PACKETIQ_LIVE_IFACE = "Ethernet"
```

## Expected test result

```
30 passed, 1 skipped
```

The skipped test is the live capture test.

## Security

- The repository contains no API keys or passwords. Put local secrets in `.env`, which Git ignores.
- The sample file uses only documentation addresses and example.com.
- Real PCAP files are ignored by Git.
