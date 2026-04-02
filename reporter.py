"""
HTML Report Generator — produces a self-contained HTML report.
"""

import os
from datetime import datetime


def _severity_badge(severity: str) -> str:
    colors = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#3b82f6"}
    color = colors.get(severity, "#6b7280")
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600">{severity}</span>'


def generate_html_report(result: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = f"reports/report_{ts}.html"

    # Protocol chart data
    proto_labels = list(result["protocols"].keys())
    proto_values = list(result["protocols"].values())

    # Anomaly rows
    anomaly_rows = ""
    if result["anomalies"]:
        for a in result["anomalies"]:
            anomaly_rows += f"""
            <tr>
                <td>{_severity_badge(a['severity'])}</td>
                <td><code>{a['type']}</code></td>
                <td><code>{a['src_ip']}</code></td>
                <td>{a['detail']}</td>
            </tr>"""
    else:
        anomaly_rows = '<tr><td colspan="4" style="text-align:center;color:#22c55e">✅ No anomalies detected</td></tr>'

    # Top IPs table
    src_ip_rows = "".join(
        f"<tr><td><code>{ip}</code></td><td>{count}</td></tr>"
        for ip, count in result["top_src_ips"]
    )
    dst_ip_rows = "".join(
        f"<tr><td><code>{ip}</code></td><td>{count}</td></tr>"
        for ip, count in result["top_dst_ips"]
    )

    well_known = {80:"HTTP", 443:"HTTPS", 53:"DNS", 22:"SSH",
                  21:"FTP", 25:"SMTP", 3306:"MySQL", 5432:"PostgreSQL"}
    port_rows = "".join(
        f"<tr><td>{port}</td><td>{well_known.get(port,'—')}</td><td>{count}</td></tr>"
        for port, count in result["top_ports"]
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Traffic Analysis Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; }}
  header {{ background: linear-gradient(135deg, #1e3a5f, #0e7490); padding: 2rem; }}
  header h1 {{ font-size: 1.6rem; font-weight: 700; }}
  header p  {{ color: #94a3b8; margin-top: .4rem; font-size: .9rem; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: #1e293b; border-radius: 12px; padding: 1.2rem; border: 1px solid #334155; }}
  .stat-card .label {{ font-size: .75rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; }}
  .stat-card .value {{ font-size: 2rem; font-weight: 700; margin-top: .3rem; color: #38bdf8; }}
  .card {{ background: #1e293b; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
  .card h2 {{ font-size: 1rem; font-weight: 600; color: #94a3b8; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: .05em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .875rem; }}
  th {{ text-align: left; padding: .6rem .8rem; color: #64748b; font-weight: 600; font-size: .75rem; text-transform: uppercase; border-bottom: 1px solid #334155; }}
  td {{ padding: .55rem .8rem; border-bottom: 1px solid #1e293b; }}
  tr:hover td {{ background: #263348; }}
  code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: .85em; }}
  .chart-wrap {{ max-width: 480px; margin: 0 auto; }}
  .anomaly-count {{ font-size: 2rem; font-weight: 700; color: {"#ef4444" if result["anomalies"] else "#22c55e"}; }}
</style>
</head>
<body>

<header>
  <h1>🔍 Network Traffic Analysis Report</h1>
  <p>File: <strong>{result['file']}</strong> &nbsp;|&nbsp; Analyzed: {result['analyzed_at'][:19].replace('T',' ')}</p>
</header>

<div class="container">

  <!-- Summary Cards -->
  <div class="stats">
    <div class="stat-card">
      <div class="label">Total Packets</div>
      <div class="value">{result['total_packets']:,}</div>
    </div>
    <div class="stat-card">
      <div class="label">Protocols</div>
      <div class="value">{len(result['protocols'])}</div>
    </div>
    <div class="stat-card">
      <div class="label">Unique Src IPs</div>
      <div class="value">{len(result['top_src_ips'])}</div>
    </div>
    <div class="stat-card">
      <div class="label">Anomalies</div>
      <div class="anomaly-count">{len(result['anomalies'])}</div>
    </div>
  </div>

  <!-- Protocol Chart -->
  <div class="card">
    <h2>📦 Protocol Distribution</h2>
    <div class="chart-wrap">
      <canvas id="protoChart"></canvas>
    </div>
  </div>

  <!-- Anomalies -->
  <div class="card">
    <h2>⚠️ Anomalies</h2>
    <table>
      <thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Detail</th></tr></thead>
      <tbody>{anomaly_rows}</tbody>
    </table>
  </div>

  <!-- Top IPs -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">
    <div class="card">
      <h2>🌐 Top Source IPs</h2>
      <table>
        <thead><tr><th>IP</th><th>Packets</th></tr></thead>
        <tbody>{src_ip_rows}</tbody>
      </table>
    </div>
    <div class="card">
      <h2>🎯 Top Destination IPs</h2>
      <table>
        <thead><tr><th>IP</th><th>Packets</th></tr></thead>
        <tbody>{dst_ip_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Top Ports -->
  <div class="card">
    <h2>🔌 Top Destination Ports</h2>
    <table>
      <thead><tr><th>Port</th><th>Service</th><th>Packets</th></tr></thead>
      <tbody>{port_rows}</tbody>
    </table>
  </div>

</div>

<script>
const ctx = document.getElementById('protoChart').getContext('2d');
new Chart(ctx, {{
  type: 'doughnut',
  data: {{
    labels: {proto_labels},
    datasets: [{{
      data: {proto_values},
      backgroundColor: ['#38bdf8','#818cf8','#34d399','#fb923c','#f472b6','#a78bfa','#facc15','#60a5fa'],
      borderWidth: 2,
      borderColor: '#0f172a'
    }}]
  }},
  options: {{
    plugins: {{
      legend: {{ labels: {{ color: '#e2e8f0' }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    return out_path
