"""Generate sample_pcaps/attack_demo.pcap: synthetic traffic that exercises all five rules.

Fully synthetic and deterministic. Addresses use the documentation ranges
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); nothing is real traffic.

Scenarios (each is separated in time so alerts are easy to attribute)
  t=  0 s  benign   : two complete HTTP handshakes + one normal DNS lookup
  t= 10 s  RULE-001 : 198.51.100.77 SYN-probes 30 ports on 192.0.2.10 (0.1 s apart)
  t= 20 s  RULE-003 : 198.51.100.88 opens 130 connections to 192.0.2.20:80 (0.02 s apart,
                      each completes its handshake, so RULE-005 stays quiet)
  t= 30 s  RULE-005 : 200 spoofed sources send one SYN each to 192.0.2.30:80 (0.01 s apart)
  t= 40 s  RULE-002 : one flow of 1200 packets x 9000 bytes (10.8 MB) over 60 s. The PCAP is
                      "snaplen-truncated" like `tcpdump -s 60`: only headers are stored, but
                      each record keeps its original wire length, so the file stays small.
  t=110 s  RULE-004 : a 66-character query and a high-entropy-label query
"""
import struct
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw

BASE = 1_790_100_000  # fixed epoch seconds -> deterministic file
MAC_A, MAC_B = "02:00:00:00:00:0a", "02:00:00:00:00:14"
records = []  # (timestamp_us, frame_bytes, original_length)


def add(t_seconds, pkt, wire_len=None, snap=None):
    raw = bytes(pkt)
    orig = wire_len if wire_len is not None else len(raw)
    if snap is not None:
        raw = raw[:snap]
    records.append((int(round((BASE + t_seconds) * 1_000_000)), raw, orig))


def tcp(src, dst, sport, dport, flags, payload=b""):
    p = Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return p / Raw(payload) if payload else p


# --- benign background --- #

for i, (client, sport) in enumerate([("192.0.2.101", 50001), ("192.0.2.102", 50002)]):
    t0 = 0.5 + i
    add(t0, tcp(client, "198.51.100.200", sport, 80, "S"))
    add(t0 + 0.01, tcp("198.51.100.200", client, 80, sport, "SA"))
    add(t0 + 0.02, tcp(client, "198.51.100.200", sport, 80, "A"))
    add(t0 + 0.03, tcp(client, "198.51.100.200", sport, 80, "PA", b"GET / HTTP/1.1\r\n\r\n"))


def dns(t, client, sport, name):
    add(t, Ether(src=MAC_A, dst=MAC_B) / IP(src=client, dst="192.0.2.53")
        / UDP(sport=sport, dport=53) / DNS(id=sport & 0xFFFF, rd=1, qd=DNSQR(qname=name)))


dns(3.0, "192.0.2.101", 53001, "example.com")

# --- RULE-001: port scan --- #

for i in range(30):
    add(10 + i * 0.1, tcp("198.51.100.77", "192.0.2.10", 44000, 1000 + i, "S"))

# --- RULE-003: high-frequency connects (each connection completes) --- #

for i in range(130):
    t = 20 + i * 0.02
    sport = 40000 + i
    add(t, tcp("198.51.100.88", "192.0.2.20", sport, 80, "S"))
    add(t + 0.005, tcp("198.51.100.88", "192.0.2.20", sport, 80, "A"))

# --- RULE-005: SYN flood from spoofed sources --- #

for i in range(200):
    add(30 + i * 0.01, tcp(f"203.0.113.{i % 250 + 1}", "192.0.2.30", 1024 + i, 80, "S"))

# --- RULE-002: one large flow, header-only capture --- #

add(40.0, tcp("192.0.2.40", "198.51.100.50", 51000, 443, "S"))
for i in range(1200):
    add(40.1 + i * 0.05, tcp("192.0.2.40", "198.51.100.50", 51000, 443, "A"), wire_len=9000, snap=54)

# --- RULE-004: suspicious DNS --- #

dns(110.0, "192.0.2.60", 53100, "a" * 20 + "." + "b" * 20 + "." + "c" * 12 + ".example.com")  # 66 chars
dns(111.0, "192.0.2.60", 53101, "x7k2q9m4z8p1w5v3n6.exfil.example")  # high-entropy label

# --- write classic little-endian PCAP (link type 1 = Ethernet) --- #

records.sort(key=lambda r: r[0])
out = Path(__file__).resolve().parent.parent / "sample_pcaps" / "attack_demo.pcap"
out.parent.mkdir(exist_ok=True)
with open(out, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts_us, raw, orig in records:
        fh.write(struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000, len(raw), orig))
        fh.write(raw)
print(f"wrote {len(records)} packets -> {out} ({out.stat().st_size} bytes)")
