#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auto_block.py - ավտոմատ IP արգելափակման սկրիպտ
Տարբերակ 1.0 (բնօրինակ - դիպլոմային աշխատանք)

Աշխատանքի սկզբունքը:
1. Վերլուծում է /var/log/nginx/attack.log ֆայլը
2. Հաշվում 429 պատասխանները ըստ IP-ի
3. Եթե IP-ն ստացել է THRESHOLD-ից շատ 429-ներ՝
   ավելացնում է blocked_ips.conf-ում որպես deny կանոն
4. Reload-ում է Nginx-ը

Գործարկվում է cron-ով՝ յուրաքանչյուր րոպե:
* * * * * /usr/bin/python3 /home/khangaldyanm/auto_block.py
"""

import subprocess
import os

LOG_FILE = "/var/log/nginx/attack.log"
BLOCK_FILE = "/etc/nginx/blocked_ips.conf"
THRESHOLD = 10


def get_suspicious_ips():
    """Վերադարձնում է 429-անոց IP-ները հաշվարկով:"""
    cmd = f"tail -n 100 {LOG_FILE} | grep ' 429 ' | awk '{{print $1}}' | sort | uniq -c | sort -nr"
    result = subprocess.getoutput(cmd)
    return result.split('\n')


def get_blocked_ips():
    """Կարդում է արդեն արգելափակված IP-ները:"""
    if not os.path.exists(BLOCK_FILE):
        return set()
    with open(BLOCK_FILE, "r") as f:
        ips = set()
        for line in f:
            line = line.strip()
            if line.startswith("deny ") and line.endswith(";"):
                ip = line[5:-1].strip()
                ips.add(ip)
        return ips


def add_to_blocklist(ip):
    """Ավելացնում է IP-ն blocked_ips.conf ֆայլում:"""
    with open(BLOCK_FILE, "a") as f:
        f.write(f"deny {ip};\n")
    print(f"[+] Blocked: {ip}")


def reload_nginx():
    """Reload-ում է Nginx-ը նոր կանոնները կիրառելու համար:"""
    subprocess.run(["sudo", "systemctl", "reload", "nginx"])


def main():
    blocked = get_blocked_ips()
    new_blocks = 0

    for line in get_suspicious_ips():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        try:
            count = int(parts[0])
            ip = parts[1]
        except ValueError:
            continue

        if count > THRESHOLD and ip not in blocked:
            add_to_blocklist(ip)
            blocked.add(ip)
            new_blocks += 1

    if new_blocks > 0:
        reload_nginx()
        print(f"[i] Reloaded Nginx ({new_blocks} new blocks)")


if __name__ == "__main__":
    main()
