"""
Generates a sample .pcap file for testing without needing real traffic.
Creates various packet types including port scan patterns.
"""

from scapy.all import (
    wrpcap, IP, TCP, UDP, ICMP, Ether, DNS, DNSQR, Raw
)
import random

random.seed(42)

packets = []

normal_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "10.0.0.5"]
server_ip  = "93.184.216.34"   # example.com

# ── Normal HTTPS traffic ──────────────────────────────────────────────────────
for _ in range(80):
    src = random.choice(normal_ips)
    pkt = (Ether() /
           IP(src=src, dst=server_ip) /
           TCP(sport=random.randint(49152, 65535), dport=443, flags="PA") /
           Raw(b"X" * random.randint(40, 200)))
    packets.append(pkt)

# ── Normal HTTP traffic ───────────────────────────────────────────────────────
for _ in range(40):
    src = random.choice(normal_ips)
    pkt = (Ether() /
           IP(src=src, dst=server_ip) /
           TCP(sport=random.randint(49152, 65535), dport=80, flags="PA") /
           Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    packets.append(pkt)

# ── Normal DNS queries ────────────────────────────────────────────────────────
domains = ["example.com", "google.com", "github.com", "stackoverflow.com"]
for _ in range(20):
    src = random.choice(normal_ips)
    pkt = (Ether() /
           IP(src=src, dst="8.8.8.8") /
           UDP(sport=random.randint(1024, 65535), dport=53) /
           DNS(rd=1, qd=DNSQR(qname=random.choice(domains))))
    packets.append(pkt)

# ── PORT SCAN simulation (attacker IP sends many SYN packets) ─────────────────
attacker = "172.16.0.99"
for port in range(1, 120):          # 119 SYN packets → triggers alert
    pkt = (Ether() /
           IP(src=attacker, dst="192.168.1.10") /
           TCP(sport=random.randint(49152, 65535), dport=port, flags="S"))
    packets.append(pkt)

# ── ICMP flood simulation ─────────────────────────────────────────────────────
flooder = "10.10.10.5"
for _ in range(120):                # 120 ICMP → triggers alert
    pkt = (Ether() /
           IP(src=flooder, dst="192.168.1.10") /
           ICMP())
    packets.append(pkt)

# ── Suspicious DNS (many queries from one host) ───────────────────────────────
dns_bot = "192.168.1.77"
for i in range(35):
    pkt = (Ether() /
           IP(src=dns_bot, dst="8.8.8.8") /
           UDP(sport=random.randint(1024, 65535), dport=53) /
           DNS(rd=1, qd=DNSQR(qname=f"sub{i}.suspiciousdomain.xyz")))
    packets.append(pkt)

# ── SSH traffic ───────────────────────────────────────────────────────────────
for _ in range(15):
    pkt = (Ether() /
           IP(src="192.168.1.10", dst="10.0.0.1") /
           TCP(sport=random.randint(49152, 65535), dport=22, flags="PA") /
           Raw(b"\x00" * 64))
    packets.append(pkt)

random.shuffle(packets)

out = "samples/sample_traffic.pcap"
wrpcap(out, packets)
print(f"[✓] Sample pcap created: {out}  ({len(packets)} packets)")
print("    Includes: HTTPS, HTTP, DNS, SSH, port scan, ICMP flood, suspicious DNS")
