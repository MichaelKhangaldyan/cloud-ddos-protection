# -*- coding: utf-8 -*-
"""
Helper module for the Flask analytics page (port 5000).

Use functions from this module to add the "Time until unban" column
to the ban table in the dashboard.
"""

import json
import os
import time

DB_FILE = "/var/lib/smart_block/bans.json"


def format_time_remaining(ban_until: int) -> str:
    """Returns a human-readable string of time until unban.

    Examples:
      4 days 3 hours       -> "4d 3h"
      45 minutes           -> "45m"
      already expired      -> "Expired"
    """
    now = int(time.time())
    remaining = ban_until - now

    if remaining <= 0:
        return "Expired"

    days = remaining // 86400
    hours = (remaining % 86400) // 3600
    minutes = (remaining % 3600) // 60
    seconds = remaining % 60

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 and days == 0:        # show minutes only if < 1 day
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{seconds}s")
    return " ".join(parts)


def format_timestamp(ts: int) -> str:
    """Unix timestamp -> 'YYYY-MM-DD HH:MM:SS'."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def load_bans():
    """Returns a list of dicts with enriched fields for the template.

    Each item:
        ip             — IP address
        strikes        — strike count (1, 2, 3)
        last_violation — Unix timestamp of last violation
        ban_until      — Unix timestamp when ban expires
        is_active      — True if ban still in effect
        time_left      — string "2d 5h" or "Expired"
        ban_until_str  — formatted end-of-ban date
        last_str       — formatted last-violation date
        progress       — percent of ban time elapsed (0-100), for progress bar
    """
    if not os.path.exists(DB_FILE):
        return []

    with open(DB_FILE, "r") as f:
        raw = json.load(f)

    now = int(time.time())
    items = []
    for ip, d in raw.items():
        ban_until = d.get("ban_until", 0)
        last = d.get("last_violation", 0)
        strikes = d.get("strikes", 0)
        total_duration = ban_until - last
        elapsed = now - last
        progress = 100
        if total_duration > 0 and elapsed < total_duration:
            progress = int((elapsed / total_duration) * 100)

        items.append({
            "ip": ip,
            "strikes": strikes,
            "last_violation": last,
            "ban_until": ban_until,
            "is_active": ban_until > now,
            "time_left": format_time_remaining(ban_until),
            "ban_until_str": format_timestamp(ban_until),
            "last_str": format_timestamp(last),
            "progress": progress,
        })

    # Sort: active bans first; within active, by time-until-unban descending
    items.sort(key=lambda x: (not x["is_active"], -x["ban_until"]))
    return items


# ====================== Example Flask integration ======================
#
# from flask import Flask, render_template_string
# from analytics_helper import load_bans
#
# app = Flask(__name__)
#
# TEMPLATE = """
# <!doctype html>
# <html><head>
#   <meta charset="utf-8">
#   <title>Banned IPs</title>
#   <meta http-equiv="refresh" content="30">  <!-- auto-refresh every 30s -->
#   <style>
#     body { font-family: Arial, sans-serif; background:#1e1e2e; color:#cdd6f4;
#            padding:20px; }
#     table { border-collapse: collapse; width: 100%; margin-top: 10px; }
#     th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #45475a; }
#     th { background: #313244; }
#     tr.active { background: rgba(243, 139, 168, 0.1); }
#     tr.expired { color: #6c7086; }
#     .badge { padding: 3px 10px; border-radius: 12px; font-size: 12px; }
#     .badge-active { background:#f38ba8; color:#11111b; }
#     .badge-expired { background:#45475a; color:#cdd6f4; }
#     .strikes-1 { color:#f9e2af; } .strikes-2 { color:#fab387; } .strikes-3 { color:#f38ba8; }
#     .bar { width: 100%; height: 8px; background:#313244; border-radius:4px;
#            overflow:hidden; }
#     .bar-fill { height:100%; background: linear-gradient(90deg,#a6e3a1,#f9e2af,#f38ba8); }
#   </style>
# </head><body>
#   <h1>Banned IPs ({{ bans|length }})</h1>
#   <table>
#     <tr>
#       <th>IP</th><th>Strikes</th><th>Status</th>
#       <th>Last violation</th><th>Ban until</th>
#       <th>Time left</th><th>Progress</th>
#     </tr>
#     {% for b in bans %}
#     <tr class="{{ 'active' if b.is_active else 'expired' }}">
#       <td>{{ b.ip }}</td>
#       <td class="strikes-{{ b.strikes }}">{{ b.strikes }}/3</td>
#       <td>
#         <span class="badge {{ 'badge-active' if b.is_active else 'badge-expired' }}">
#           {{ 'ACTIVE' if b.is_active else 'EXPIRED' }}
#         </span>
#       </td>
#       <td>{{ b.last_str }}</td>
#       <td>{{ b.ban_until_str }}</td>
#       <td><b>{{ b.time_left }}</b></td>
#       <td>
#         {% if b.is_active %}
#           <div class="bar"><div class="bar-fill" style="width: {{ b.progress }}%"></div></div>
#         {% else %}
#           —
#         {% endif %}
#       </td>
#     </tr>
#     {% endfor %}
#   </table>
# </body></html>
# """
#
# @app.route("/")
# def index():
#     return render_template_string(TEMPLATE, bans=load_bans())
#
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000)
