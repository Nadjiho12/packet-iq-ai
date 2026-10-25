"""Generate sample_pcaps/sample.pcap: 12 fully synthetic packets.

No real traffic is involved. Addresses come from the documentation ranges
(RFC 5737 IPv4: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; RFC 3849 IPv6:
2001:db8::/32) and the domain is example.com, so the file is safe to share.
Timestamps are fixed, so the output is deterministic.
"""
from pathlib import Path

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether,
                       ICMPv6EchoRequest, IPv6, Raw, wrpcap)

CLIENT_MAC, SERVER_MAC = "02:00:00:00:00:0a", "02:00:00:00:00:14"
BASE_TS = 1_790_000_000.0  # fixed epoch -> deterministic file


def eth():
    return Ether(src=CLIENT_MAC, dst=SERVER_MAC)


packets = [
    # 0-2  TCP handshake start + HTTP request (192.0.2.10 -> 198.51.100.20:80)
    eth() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=49152, dport=80, flags="S", seq=100),
    eth() / IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=80, dport=49152, flags="SA", seq=500, ack=101),
    eth() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=49152, dport=80, flags="PA", seq=101, ack=501)
    / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    # 3-4  DNS query + response
    eth() / IP(src="192.0.2.10", dst="192.0.2.53") / UDP(sport=53000, dport=53)
    / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com")),
    eth() / IP(src="192.0.2.53", dst="192.0.2.10") / UDP(sport=53, dport=53000)
    / DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"),
          an=DNSRR(rrname="example.com", ttl=60, rdata="198.51.100.20")),
    # 5    plain UDP
    eth() / IP(src="192.0.2.10", dst="203.0.113.5") / UDP(sport=40000, dport=9999) / Raw(b"hello"),
    # 6    ICMP echo request
    eth() / IP(src="192.0.2.10", dst="198.51.100.20") / ICMP(type=8, id=1, seq=1),
    # 7    ARP who-has (non-IP frame)
    Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=CLIENT_MAC, psrc="192.0.2.10", pdst="192.0.2.1"),
    # 8    IPv6 TCP SYN to 443
    eth() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=443, flags="S"),
    # 9    ICMPv6 echo request
    eth() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(id=1, seq=1),
    # 10   IPv4 with experimental protocol number 253 (no recognised transport layer)
    eth() / IP(src="192.0.2.10", dst="198.51.100.20", proto=253) / Raw(b"\x01\x02\x03\x04"),
    # 11   Ethernet frame with a local-experimental ethertype (no IP layer at all)
    Ether(src=CLIENT_MAC, dst=SERVER_MAC, type=0x88B5) / Raw(b"\xde\xad\xbe\xef"),
]
for i, p in enumerate(packets):
    p.time = BASE_TS + i * 0.25

out = Path(__file__).resolve().parent.parent / "sample_pcaps" / "sample.pcap"
out.parent.mkdir(exist_ok=True)
wrpcap(str(out), packets)
print(f"wrote {len(packets)} packets -> {out}")
