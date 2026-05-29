#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Smart DDoS Protection — two-level blocking system.

Protection layers:
  1. iptables DROP (L3/L4) — packets dropped by kernel before reaching nginx.
  2. nginx deny       (L7) — fallback in case iptables doesn't catch it (returns 403).

Strike logic:
  1st strike  → ban for 24 hours
  2nd strike  → ban for 5 days
  3rd strike  → ban for 30 days
  If an IP doesn't attack for 30 days — strike counter resets.

Automatic unban:
  On every run, the script removes iptables + nginx rules for IPs
  whose ban_until has expired. Records stay in bans.json for 30 more days
  (for strike escalation), then are deleted entirely.

Run via systemd-timer once per minute.
"""

import json
import logging
import os
import subprocess
import time
from logging.handlers import RotatingFileHandler

# ============================ Configuration ============================

LOG_FILE       = "/var/log/nginx/attack.log"
BLOCK_FILE     = "/etc/nginx/blocked_ips.conf"
DB_FILE        = "/var/lib/smart_block/bans.json"
ACTION_LOG     = "/var/log/smart_block.log"
IPTABLES_CHAIN = "SMART_BLOCK"

# How many 429 responses in the sample window trigger a strike
THRESHOLD   = 5
# How many recent log lines to analyze per run
TAIL_LINES  = 200
# After how many days without attacks the strike counter resets
RESET_DAYS  = 30

# Ban duration by strike count (in seconds)
BAN_TIMES = {
    1: 86400,        # 24 hours
    2: 432000,       # 5 days
    3: 2592000,      # 30 days
}

# ============================ Logging ============================

def setup_logger():
    logger = logging.getLogger("smart_block")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    # File handler with rotation
    fh = RotatingFileHandler(ACTION_LOG, maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    # Stdout handler (for journalctl / cron)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

log = setup_logger()

# ============================ Database ============================

def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.error(f"Cannot read {DB_FILE}: {e}. Starting with empty DB.")
        return {}

def save_db(db):
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(db, f, indent=4)
    os.replace(tmp, DB_FILE)

# ============================ iptables ============================

def run(cmd, check=False):
    """Convenience wrapper for subprocess."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)

def ensure_iptables_chain():
    """Create SMART_BLOCK chain and hook it into INPUT if not present yet."""
    r = run(["iptables", "-L", IPTABLES_CHAIN, "-n"])
    if r.returncode != 0:
        run(["iptables", "-N", IPTABLES_CHAIN], check=True)
        log.info(f"Created iptables chain {IPTABLES_CHAIN}")

    # Hook the chain into INPUT (at the very top) if not already
    r = run(["iptables", "-C", "INPUT", "-j", IPTABLES_CHAIN])
    if r.returncode != 0:
        run(["iptables", "-I", "INPUT", "1", "-j", IPTABLES_CHAIN], check=True)
        log.info(f"Chain {IPTABLES_CHAIN} attached to INPUT")

def iptables_current_blocks():
    """Return set of IPs currently DROP'd in SMART_BLOCK chain."""
    r = run(["iptables", "-S", IPTABLES_CHAIN])
    ips = set()
    for line in r.stdout.splitlines():
        # format: -A SMART_BLOCK -s 35.223.216.81/32 -j DROP
        parts = line.split()
        if "-s" in parts and "-j" in parts and parts[parts.index("-j") + 1] == "DROP":
            ip = parts[parts.index("-s") + 1].split("/")[0]
            ips.add(ip)
    return ips

def iptables_block(ip):
    r = run(["iptables", "-C", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])
    if r.returncode != 0:
        run(["iptables", "-A", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"], check=True)
        log.warning(f"iptables: DROP added for {ip}")

def iptables_unblock(ip):
    # Remove all matching rules (in case of duplicates)
    while True:
        r = run(["iptables", "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])
        if r.returncode != 0:
            break
    log.info(f"iptables: DROP removed for {ip}")

# ========================= Access log analysis =========================

def get_429_ips():
    """Return list of (count, ip) for IPs with 429 in the TAIL_LINES most recent lines."""
    cmd = (
        f"tail -n {TAIL_LINES} {LOG_FILE} 2>/dev/null "
        f"| grep ' 429 ' "
        f"| awk '{{print $1}}' "
        f"| sort | uniq -c | sort -nr"
    )
    out = subprocess.getoutput(cmd)
    result = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        try:
            result.append((int(parts[0]), parts[1]))
        except ValueError:
            continue
    return result

# ========================== Strike processing ========================

def process_violation(db, ip):
    """Register a violation for an IP. Returns True if a new ban was issued."""
    now = int(time.time())

    # Already banned — do nothing
    if ip in db and db[ip].get("ban_until", 0) > now:
        return False

    if ip not in db:
        strikes = 1
    else:
        last = db[ip].get("last_violation", 0)
        days_since = (now - last) / 86400
        if days_since > RESET_DAYS:
            strikes = 1                                  # haven't attacked for a while — reset
        else:
            strikes = min(db[ip].get("strikes", 0) + 1, 3)

    ban_seconds = BAN_TIMES[strikes]
    db[ip] = {
        "strikes": strikes,
        "last_violation": now,
        "ban_until": now + ban_seconds,
    }
    log.warning(
        f"BAN  {ip}  strikes={strikes}  duration={ban_seconds//86400}d "
        f"{(ban_seconds%86400)//3600}h"
    )
    return True

# ============================ Apply state ==============================

def sync_state(db):
    """Sync bans.json -> nginx blocked_ips.conf + iptables.

    Returns True if nginx config changed (reload needed)."""
    now = int(time.time())

    # 1. Clean up old entries (strikes irrelevant after RESET_DAYS)
    stale = [ip for ip, d in db.items()
             if now - d.get("last_violation", 0) > RESET_DAYS * 86400]
    for ip in stale:
        del db[ip]
        log.info(f"CLEAN {ip} — record older than {RESET_DAYS} days, removed from DB")

    # 2. Active bans (ban_until still in the future)
    active = {ip for ip, d in db.items() if d["ban_until"] > now}

    # 3. Rewrite nginx blocked_ips.conf
    new_content = "".join(f"deny {ip};\n" for ip in sorted(active))
    old_content = ""
    if os.path.exists(BLOCK_FILE):
        with open(BLOCK_FILE, "r") as f:
            old_content = f.read()

    nginx_changed = False
    if new_content != old_content:
        with open(BLOCK_FILE, "w") as f:
            f.write(new_content)
        nginx_changed = True
        log.info(f"nginx blocked_ips.conf updated ({len(active)} active bans)")

    # 4. Sync iptables
    current = iptables_current_blocks()
    for ip in active - current:
        iptables_block(ip)
    for ip in current - active:
        iptables_unblock(ip)
        log.warning(f"UNBAN {ip} — ban expired")

    return nginx_changed

def reload_nginx():
    r = run(["systemctl", "reload", "nginx"])
    if r.returncode == 0:
        log.info("nginx reloaded")
    else:
        log.error(f"Failed to reload nginx: {r.stderr}")

# ================================ MAIN ================================

def main():
    log.info("=== smart_block run start ===")

    try:
        ensure_iptables_chain()
    except subprocess.CalledProcessError as e:
        log.error(f"Failed to configure iptables: {e}. Is script running as root?")
        return

    db = load_db()
    new_bans = 0
    for count, ip in get_429_ips():
        if count > THRESHOLD:
            if process_violation(db, ip):
                new_bans += 1

    nginx_changed = sync_state(db)
    save_db(db)

    if nginx_changed:
        reload_nginx()

    active = sum(1 for d in db.values() if d["ban_until"] > int(time.time()))
    log.info(f"=== Done. Active bans: {active}, new: {new_bans} ===")

if __name__ == "__main__":
    main()
