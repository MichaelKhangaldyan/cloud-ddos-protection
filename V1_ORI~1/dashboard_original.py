# -*- coding: utf-8 -*-
"""
dashboard.py - Flask DDoS Monitoring Dashboard
Տարբերակ 1.0 (բնօրինակ - դիպլոմային աշխատանք)

Գործարկում:
    python3 dashboard.py

URL: http://<shield-ip>:5000/
"""

from flask import Flask
from collections import Counter
import matplotlib.pyplot as plt
import os
import requests

app = Flask(__name__)

LOG_FILE = "/var/log/nginx/attack.log"
BLOCK_FILE = "/etc/nginx/blocked_ips.conf"


def get_top_ips():
    ips = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                if " 429 " in line:
                    ip = line.split()[0]
                    ips.append(ip)
    except Exception:
        pass
    return Counter(ips).most_common(10)


def get_last_logs():
    logs = []
    try:
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()[-15:]
    except Exception:
        pass
    return logs


def get_blocked_ips():
    blocked = []
    try:
        with open(BLOCK_FILE, "r") as f:
            blocked = [x.strip() for x in f.readlines()]
    except Exception:
        pass
    return blocked


def get_country(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return r.get("country", "Unknown")
    except Exception:
        return "Unknown"


def create_chart(data):
    if not data:
        return
    ips = [x[0] for x in data]
    counts = [x[1] for x in data]
    os.makedirs("static", exist_ok=True)
    plt.figure(figsize=(9, 4))
    plt.bar(ips, counts)
    plt.xlabel("IP")
    plt.ylabel("429 Count")
    plt.title("Top Suspicious IPs")
    plt.tight_layout()
    plt.savefig("static/chart.png")
    plt.close()


@app.route("/")
def dashboard():
    top_ips = get_top_ips()
    blocked_ips = get_blocked_ips()
    last_logs = get_last_logs()
    create_chart(top_ips)
    total_429 = sum([x[1] for x in top_ips])

    html = f"""
    <html>
    <head>
        <title>DDoS Dashboard</title>
        <meta http-equiv="refresh" content="5">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-dark text-light">
    <div class="container mt-4">
        <h1 class="display-4 fw-bold text-danger">Cloud DDoS Protection Dashboard</h1>
        <p class="text-secondary">Real-time monitoring and attack analysis</p>

        <div class="row mt-4">
            <div class="col-md-4">
                <div class="card bg-danger shadow-lg text-white mb-3">
                    <div class="card-body">
                        <h5>Total 429</h5>
                        <h2>{total_429}</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card bg-warning shadow-lg text-dark mb-3">
                    <div class="card-body">
                        <h5>Blocked IPs</h5>
                        <h2>{len(blocked_ips)}</h2>
                    </div>
                </div>
            </div>
        </div>

        <div class="card shadow-lg mb-4">
            <div class="card-body">
                <h3>Attack Statistics</h3>
                <img src="/static/chart.png" class="img-fluid">
            </div>
        </div>

        <div class="card shadow-lg mb-4">
            <div class="card-body">
                <h3>Top Suspicious IPs</h3>
                <table class="table table-dark table-striped">
                    <tr><th>IP</th><th>Country</th><th>429 Count</th></tr>
    """
    for ip, count in top_ips:
        country = get_country(ip)
        html += f"<tr><td>{ip}</td><td>{country}</td><td>{count}</td></tr>"
    html += """
                </table>
            </div>
        </div>

        <div class="card shadow-lg mb-4">
            <div class="card-body">
                <h3>Blocked IPs</h3>
                <table class="table table-dark table-striped"><tr><th>Rule</th></tr>
    """
    for ip in blocked_ips:
        html += f"<tr><td>{ip}</td></tr>"
    html += """
                </table>
            </div>
        </div>

        <div class="card shadow-lg mb-5">
            <div class="card-body">
                <h3>Live Attack Logs</h3>
                <table class="table table-dark table-striped"><tr><th>Log Entry</th></tr>
    """
    for log in reversed(last_logs):
        html += f"<tr><td>{log}</td></tr>"
    html += """
                </table>
            </div>
        </div>
    </div>
    </body>
    </html>
    """
    return html


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
