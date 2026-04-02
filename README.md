# 🔍 Network Traffic Analyzer

A Python-based network traffic analysis tool that parses `.pcap` files, detects anomalies, stores results in PostgreSQL, and generates both terminal and HTML reports.

---

## Features

- **Protocol Distribution** — TCP (SYN/DATA), UDP, DNS, ICMP, ARP breakdown
- **Top Talkers** — most active source/destination IPs and ports
- **Anomaly Detection:**
  - 🔴 Port Scan detection (SYN flood from single IP)
  - 🟡 ICMP Flood detection
  - 🔵 Suspicious DNS activity
- **PostgreSQL Storage** — persist all analyses and anomalies for historical querying
- **HTML Report** — self-contained dark-themed dashboard with Chart.js charts
- **CLI Interface** — simple flags, works with any `.pcap` file

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.10+ | Core language |
| Scapy | Packet parsing |
| PostgreSQL | Persistent storage |
| psycopg2 | PostgreSQL driver |
| Chart.js | HTML report charts |

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Create PostgreSQL database
```sql
CREATE DATABASE traffic_analyzer;
```

### 3. Configure database (optional — defaults to localhost/postgres)
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=traffic_analyzer
export DB_USER=postgres
export DB_PASSWORD=yourpassword
```

---

## Usage

### Generate a sample .pcap for testing
```bash
python generate_sample.py
```

### Analyze a .pcap file
```bash
python analyzer.py samples/sample_traffic.pcap
```

### Skip database or HTML report
```bash
python analyzer.py traffic.pcap --no-db
python analyzer.py traffic.pcap --no-html
python analyzer.py traffic.pcap --no-db --no-html
```

---

## Sample Output

```
════════════════════════════════════════════════════════════
  NETWORK TRAFFIC ANALYSIS REPORT
  File       : samples/sample_traffic.pcap
  Total pkts : 429
════════════════════════════════════════════════════════════

📦  PROTOCOL DISTRIBUTION
────────────────────────────────────────────────────────────
  TCP/SYN         119  ████████████
  ICMP            120  ████████████
  TCP/DATA        120  ████████████
  DNS              55  █████
  ...

⚠️  ANOMALIES DETECTED: 3
────────────────────────────────────────────────────────────
  🔴 [HIGH]   PORT_SCAN      — 172.16.0.99  (119 SYN packets)
  🟡 [MEDIUM] ICMP_FLOOD     — 10.10.10.5   (120 ICMP packets)
  🔵 [LOW]    SUSPICIOUS_DNS — 192.168.1.77 (35 DNS queries)
```

HTML report is saved to `reports/report_YYYYMMDD_HHMMSS.html`.

---

## Project Structure

```
network-traffic-analyzer/
├── analyzer.py          # Main entry point & analysis logic
├── db.py                # PostgreSQL integration
├── reporter.py          # HTML report generator
├── generate_sample.py   # Test data generator
├── requirements.txt
├── samples/             # Place your .pcap files here
└── reports/             # Generated HTML reports
```

---

## Relevant Skills Demonstrated

- Network protocols (TCP/IP, UDP, DNS, ICMP)
- Packet analysis with Scapy
- Anomaly/intrusion detection concepts
- PostgreSQL schema design with JSONB
- Python CLI tooling

---

## License

MIT
