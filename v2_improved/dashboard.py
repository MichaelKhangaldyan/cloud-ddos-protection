from flask import Flask
from collections import Counter
import matplotlib
matplotlib.use("Agg")          # headless chart rendering (no X server)
import matplotlib.pyplot as plt
import os
import json
import time
import requests

app = Flask(__name__)

LOG_FILE   = "/var/log/nginx/attack.log"
BLOCK_FILE = "/etc/nginx/blocked_ips.conf"
DB_FILE    = "/var/lib/smart_block/bans.json"

# ===================================================================
#  Ban helpers
# ===================================================================

def format_time_remaining(ban_until):
    """Returns '4d 3h', '45m' or 'Expired'."""
    remaining = ban_until - int(time.time())
    if remaining <= 0:
        return "Expired"
    days = remaining // 86400
    hours = (remaining % 86400) // 3600
    minutes = (remaining % 3600) // 60
    parts = []
    if days > 0: parts.append(f"{days}d")
    if hours > 0: parts.append(f"{hours}h")
    if minutes > 0 and days == 0: parts.append(f"{minutes}m")
    if not parts: parts.append(f"{remaining}s")
    return " ".join(parts)

def format_ts(ts):
    """Unix timestamp -> 'YYYY-MM-DD HH:MM:SS'."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

def load_bans():
    """Read bans.json and return enriched list of ban records."""
    if not os.path.exists(DB_FILE):
        return []
    try:
        with open(DB_FILE, "r") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    now = int(time.time())
    items = []
    for ip, d in raw.items():
        ban_until = d.get("ban_until", 0)
        last      = d.get("last_violation", 0)
        strikes   = d.get("strikes", 0)
        total     = ban_until - last
        elapsed   = now - last
        progress  = 100
        if total > 0 and elapsed < total:
            progress = int((elapsed / total) * 100)
        items.append({
            "ip": ip, "strikes": strikes,
            "is_active": ban_until > now,
            "time_left": format_time_remaining(ban_until),
            "ban_until_str": format_ts(ban_until),
            "last_str": format_ts(last),
            "progress": progress, "ban_until": ban_until,
        })
    # Active bans first, sort by longest remaining ban
    items.sort(key=lambda x: (not x["is_active"], -x["ban_until"]))
    return items

# ===================================================================
#  Log / chart / GeoIP helpers
# ===================================================================

def get_top_ips():
    ips = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                if " 429 " in line:
                    ips.append(line.split()[0])
    except Exception: pass
    return Counter(ips).most_common(10)

def get_last_logs():
    try:
        with open(LOG_FILE, "r") as f:
            return f.readlines()[-15:]
    except Exception:
        return []

# Cache country lookups to avoid hitting ip-api.com on every refresh (limit 45/min)
_geo_cache = {}
def get_country(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        country = r.get("country", "Unknown")
    except Exception:
        country = "Unknown"
    _geo_cache[ip] = country
    return country

def create_chart(data):
    if not data: return
    ips    = [x[0] for x in data]
    counts = [x[1] for x in data]
    os.makedirs("static", exist_ok=True)
    plt.figure(figsize=(9, 4))
    plt.bar(ips, counts, color="#f38ba8")
    plt.xlabel("IP"); plt.ylabel("429 Count"); plt.title("Top Suspicious IPs")
    plt.xticks(rotation=20); plt.tight_layout()
    plt.savefig("static/chart.png"); plt.close()

# ===================================================================
#  Dashboard route
# ===================================================================

@app.route("/")
def dashboard():
    top_ips      = get_top_ips()
    bans         = load_bans()
    last_logs    = get_last_logs()
    create_chart(top_ips)
    total_429    = sum(x[1] for x in top_ips)
    active_count = sum(1 for b in bans if b["is_active"])

    html = f"""
    <html><head>
        <title>DDoS Dashboard</title>
        <meta http-equiv="refresh" content="10">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .strike-1 {{ color: #f9e2af; font-weight: bold; }}
            .strike-2 {{ color: #fab387; font-weight: bold; }}
            .strike-3 {{ color: #f38ba8; font-weight: bold; }}
            .badge-active {{ background: #f38ba8; color: #11111b; }}
            .badge-expired {{ background: #45475a; color: #cdd6f4; }}
            .progress-thin {{ height: 6px; }}
            .progress-bar-ban {{ background: linear-gradient(90deg, #a6e3a1, #f9e2af, #f38ba8); }}
            .time-left {{ font-family: monospace; font-size: 1.1em; }}
            .expired-row {{ opacity: 0.5; }}
        </style>
    </head><body class="bg-dark text-light">
    <div class="container mt-4">
        <h1 class="display-4 fw-bold text-danger">Cloud DDoS Protection Dashboard</h1>
        <p class="text-secondary">Real-time monitoring and attack analysis</p>

        <div class="row mt-4">
            <div class="col-md-4"><div class="card bg-danger shadow-lg text-white mb-3"><div class="card-body">
                <h5>Total 429</h5><h2>{total_429}</h2></div></div></div>
            <div class="col-md-4"><div class="card bg-warning shadow-lg text-dark mb-3"><div class="card-body">
                <h5>Active Bans</h5><h2>{active_count}</h2></div></div></div>
            <div class="col-md-4"><div class="card bg-info shadow-lg text-dark mb-3"><div class="card-body">
                <h5>Total Records</h5><h2>{len(bans)}</h2></div></div></div>
        </div>

        <div class="card shadow-lg mb-4"><div class="card-body">
            <h3>Attack Statistics</h3>
            <img src="/static/chart.png" class="img-fluid">
        </div></div>

        <div class="card shadow-lg mb-4"><div class="card-body">
            <h3>Top Suspicious IPs</h3>
            <table class="table table-dark table-striped">
                <tr><th>IP</th><th>Country</th><th>429 Count</th></tr>
    """
    for ip, count in top_ips:
        html += f"<tr><td>{ip}</td><td>{get_country(ip)}</td><td>{count}</td></tr>"
    html += """
            </table>
        </div></div>

        <div class="card shadow-lg mb-4"><div class="card-body">
            <h3>Banned IPs &mdash; with countdown to unban</h3>
            <table class="table table-dark table-striped align-middle">
                <thead><tr>
                    <th>IP</th><th>Strikes</th><th>Status</th>
                    <th>Last violation</th><th>Ban until</th>
                    <th>Time left</th><th style="min-width: 140px;">Progress</th>
                </tr></thead><tbody>
    """
    if not bans:
        html += """
        <tr><td colspan="7" class="text-center text-secondary">
            No records. bans.json is empty or not yet created by smart_block.py.
        </td></tr>"""
    else:
        for b in bans:
            row_class   = "" if b["is_active"] else "expired-row"
            badge_class = "badge-active" if b["is_active"] else "badge-expired"
            status_text = "ACTIVE" if b["is_active"] else "EXPIRED"
            progress_html = (
                f'<div class="progress progress-thin">'
                f'<div class="progress-bar progress-bar-ban" style="width: {b["progress"]}%"></div></div>'
                if b["is_active"] else '<span class="text-secondary">&mdash;</span>'
            )
            html += f"""
            <tr class="{row_class}">
                <td><code>{b["ip"]}</code></td>
                <td><span class="strike-{b["strikes"]}">{b["strikes"]}/3</span></td>
                <td><span class="badge {badge_class}">{status_text}</span></td>
                <td><small>{b["last_str"]}</small></td>
                <td><small>{b["ban_until_str"]}</small></td>
                <td class="time-left">{b["time_left"]}</td>
                <td>{progress_html}</td>
            </tr>"""
    html += """
                </tbody>
            </table>
        </div></div>

        <div class="card shadow-lg mb-5"><div class="card-body">
            <h3>Live Attack Logs</h3>
            <table class="table table-dark table-striped"><tr><th>Log Entry</th></tr>
    """
    for line in reversed(last_logs):
        html += f"<tr><td><code>{line}</code></td></tr>"
    html += """
            </table>
        </div></div>
    </div></body></html>
    """
    return html

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
