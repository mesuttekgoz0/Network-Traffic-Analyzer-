"""
Network Traffic Analyzer
Analyzes .pcap files for protocol distribution, top IPs, and anomaly detection.
"""

import sys
import json
import argparse
from collections import defaultdict, Counter
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from db import Database
from reporter import generate_html_report


# ─── Thresholds ───────────────────────────────────────────────────────────────
SYN_SCAN_THRESHOLD = 50      # SYN packets from same IP → port scan alert
ICMP_FLOOD_THRESHOLD = 100   # ICMP packets from same IP → flood alert
DNS_QUERY_THRESHOLD = 30     # DNS queries from same IP → suspicious


def analyze_pcap(filepath: str) -> dict:
    print(f"\n[*] Loading: {filepath}")
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        sys.exit(1)

    print(f"[*] {len(packets)} packets loaded. Analyzing...\n")

    # ── Counters ──────────────────────────────────────────────────────────────
    protocol_counter = Counter()
    src_ip_counter   = Counter()
    dst_ip_counter   = Counter()
    port_counter     = Counter()
    syn_counter      = Counter()
    icmp_counter     = Counter()
    dns_queries      = Counter()
    ip_pairs         = Counter()
    anomalies        = []
    timeline         = []

    for pkt in packets:
        ts = float(pkt.time)

        # ── ARP ───────────────────────────────────────────────────────────────
        if ARP in pkt:
            protocol_counter["ARP"] += 1
            continue

        if IP not in pkt:
            protocol_counter["OTHER"] += 1
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        src_ip_counter[src] += 1
        dst_ip_counter[dst] += 1
        ip_pairs[(src, dst)] += 1

        # ── TCP ───────────────────────────────────────────────────────────────
        if TCP in pkt:
            flags = pkt[TCP].flags
            dport = pkt[TCP].dport

            if flags == 0x002:                      # SYN only
                protocol_counter["TCP/SYN"] += 1
                syn_counter[src] += 1
            elif flags == 0x018:                    # PSH+ACK (data)
                protocol_counter["TCP/DATA"] += 1
            else:
                protocol_counter["TCP/OTHER"] += 1

            port_counter[dport] += 1
            timeline.append({"time": ts, "src": src, "dst": dst, "proto": "TCP", "dport": dport})

        # ── UDP / DNS ─────────────────────────────────────────────────────────
        elif UDP in pkt:
            if DNS in pkt and pkt[DNS].qr == 0:    # DNS query
                protocol_counter["DNS"] += 1
                dns_queries[src] += 1
                if DNSQR in pkt:
                    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    timeline.append({"time": ts, "src": src, "dst": dst, "proto": "DNS", "query": qname})
            else:
                protocol_counter["UDP"] += 1
                timeline.append({"time": ts, "src": src, "dst": dst, "proto": "UDP"})

        # ── ICMP ──────────────────────────────────────────────────────────────
        elif ICMP in pkt:
            protocol_counter["ICMP"] += 1
            icmp_counter[src] += 1
            timeline.append({"time": ts, "src": src, "dst": dst, "proto": "ICMP"})

        else:
            protocol_counter["OTHER"] += 1

    # ── Anomaly Detection ─────────────────────────────────────────────────────
    for ip, count in syn_counter.items():
        if count >= SYN_SCAN_THRESHOLD:
            anomalies.append({
                "type":     "PORT_SCAN",
                "severity": "HIGH",
                "src_ip":   ip,
                "detail":   f"{count} SYN packets sent (threshold: {SYN_SCAN_THRESHOLD})"
            })

    for ip, count in icmp_counter.items():
        if count >= ICMP_FLOOD_THRESHOLD:
            anomalies.append({
                "type":     "ICMP_FLOOD",
                "severity": "MEDIUM",
                "src_ip":   ip,
                "detail":   f"{count} ICMP packets sent (threshold: {ICMP_FLOOD_THRESHOLD})"
            })

    for ip, count in dns_queries.items():
        if count >= DNS_QUERY_THRESHOLD:
            anomalies.append({
                "type":     "SUSPICIOUS_DNS",
                "severity": "LOW",
                "src_ip":   ip,
                "detail":   f"{count} DNS queries (threshold: {DNS_QUERY_THRESHOLD})"
            })

    return {
        "file":           filepath,
        "total_packets":  len(packets),
        "analyzed_at":    datetime.now().isoformat(),
        "protocols":      dict(protocol_counter),
        "top_src_ips":    src_ip_counter.most_common(10),
        "top_dst_ips":    dst_ip_counter.most_common(10),
        "top_ports":      port_counter.most_common(10),
        "top_ip_pairs":   [(f"{s} → {d}", c) for (s, d), c in ip_pairs.most_common(5)],
        "anomalies":      anomalies,
        "timeline":       timeline[:200],   # first 200 events for report
    }


def print_report(result: dict):
    sep = "─" * 60
    print(f"\n{'═'*60}")
    print(f"  NETWORK TRAFFIC ANALYSIS REPORT")
    print(f"  File       : {result['file']}")
    print(f"  Analyzed at: {result['analyzed_at']}")
    print(f"  Total pkts : {result['total_packets']}")
    print(f"{'═'*60}\n")

    # Protocols
    print("📦  PROTOCOL DISTRIBUTION")
    print(sep)
    total = sum(result["protocols"].values()) or 1
    for proto, count in sorted(result["protocols"].items(), key=lambda x: -x[1]):
        bar = "█" * int(count / total * 30)
        print(f"  {proto:<15} {count:>6}  {bar}")

    # Top IPs
    print(f"\n🌐  TOP SOURCE IPs")
    print(sep)
    for ip, count in result["top_src_ips"]:
        print(f"  {ip:<20} {count:>6} packets")

    print(f"\n🎯  TOP DESTINATION IPs")
    print(sep)
    for ip, count in result["top_dst_ips"]:
        print(f"  {ip:<20} {count:>6} packets")

    # Top ports
    print(f"\n🔌  TOP DESTINATION PORTS")
    print(sep)
    well_known = {80:"HTTP", 443:"HTTPS", 53:"DNS", 22:"SSH",
                  21:"FTP", 25:"SMTP", 3306:"MySQL", 5432:"PostgreSQL"}
    for port, count in result["top_ports"]:
        label = well_known.get(port, "")
        print(f"  Port {port:<7} {count:>6} packets  {label}")

    # Anomalies
    print(f"\n⚠️   ANOMALIES DETECTED: {len(result['anomalies'])}")
    print(sep)
    if not result["anomalies"]:
        print("  ✅ No anomalies detected.")
    else:
        sev_icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}
        for a in result["anomalies"]:
            icon = sev_icon.get(a["severity"], "⚪")
            print(f"  {icon} [{a['severity']}] {a['type']}")
            print(f"       Source : {a['src_ip']}")
            print(f"       Detail : {a['detail']}\n")

    print(f"{'═'*60}\n")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Network Traffic Analyzer — analyze .pcap files"
    )
    parser.add_argument("pcap", help="Path to .pcap file")
    parser.add_argument("--no-db",   action="store_true", help="Skip database storage")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    args = parser.parse_args()

    result = analyze_pcap(args.pcap)

    # Terminal report
    print_report(result)

    # HTML report
    if not args.no_html:
        html_path = generate_html_report(result)
        print(f"[✓] HTML report saved: {html_path}")

    # Database
    if not args.no_db:
        try:
            db = Database()
            db.save_analysis(result)
            print(f"[✓] Results saved to PostgreSQL.")
            db.close()
        except Exception as e:
            print(f"[!] DB skipped: {e}")
            print("    (Run with --no-db to suppress this warning)")


if __name__ == "__main__":
    main()
