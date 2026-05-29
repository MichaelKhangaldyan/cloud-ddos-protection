<div align="center">

# 🛡️ Cloud DDoS Protection System

### Multi-layered DDoS defense built on Google Cloud Platform

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Nginx](https://img.shields.io/badge/Nginx-1.22-009639?style=flat-square&logo=nginx&logoColor=white)](https://www.nginx.com/)
[![GCP](https://img.shields.io/badge/Google_Cloud-4285F4?style=flat-square&logo=googlecloud&logoColor=white)](https://cloud.google.com/)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

**Bachelor Thesis Project**  •  National University of Architecture and Construction of Armenia  •  2026

[Overview](#overview) • [Architecture](#architecture) • [Features](#features) • [Quick Start](#quick-start) • [Results](#test-results) • [Improvements](#post-review-improvements)

</div>

---

## 📋 Overview

A production-style **multi-layered DDoS protection prototype** that defends a web service hosted on Google Cloud Platform against HTTP-flood and volumetric attacks. Built around the same architectural principles used by Cloudflare, AWS Shield, and Akamai — reverse proxy, rate limiting, automated IP blocking, and real-time monitoring — but at student-project scale.

**Key result:** Under simulated attack, target server CPU load dropped from **228%** (system overwhelmed) to **under 5%** (stable operation) with the protection layer active.

> 🎓 This project was developed as my Bachelor thesis in Informatics. It demonstrates practical cybersecurity engineering — designing defensive architecture, automating responses, and iterating based on real-world feedback (including a major rework after reviewer feedback on ban policy).

---

## 🏗️ Architecture

```
                  ┌──────────────────────────────────────┐
                  │   vm-shield   (public, reverse proxy)│
                  │                                      │
   attack-vm      │  ┌───────────────┐                   │
                  │  │ iptables      │  ◄── L3/L4 layer  │
  ───────────────►│  │ SMART_BLOCK   │      packets from │
                  │  │ chain         │      banned IPs   │
                  │  │               │      dropped by   │
                  │  └───────┬───────┘      the kernel   │
                  │          │                           │
                  │  ┌───────▼────────┐                  │
                  │  │ nginx          │                  │
                  │  │  • blocked_ips │  ◄── L7 layer    │
                  │  │    (deny→403)  │                  │
                  │  │  • limit_req   │      rate limit  │
                  │  │    (1r/s→429)  │      + IP block  │
                  │  └───────┬────────┘                  │
                  │          │ proxy_pass                │
                  └──────────┼───────────────────────────┘
                             │
                  ┌──────────▼────────────┐
                  │ vm-target  (private)  │
                  │ Backend web server    │
                  └───────────────────────┘

   ┌─────────────────────────────────────────────────────┐
   │ smart_block.py  (systemd timer, every minute)       │
   │                                                     │
   │   1. Parse /var/log/nginx/attack.log                │
   │   2. Count 429 responses per IP                     │
   │   3. Apply progressive ban escalation               │
   │   4. Sync iptables DROP + nginx deny rules          │
   │   5. Auto-unban expired entries                     │
   │   6. Log all actions to /var/log/smart_block.log    │
   └─────────────────────────────────────────────────────┘
```

### Three-VM topology

| VM | Role | IP exposure |
|----|------|-------------|
| **vm-attack** | Attack simulator (curl, ab, k6) | External IP for SSH only |
| **vm-shield** | Reverse proxy + rate limit + auto-block + dashboard | **Public IP** (entry point) |
| **vm-target** | Protected web backend | **Internal IP only** — invisible from the internet |

---

## ✨ Features

### 🔒 Defense layers

- **L3/L4 packet-level blocking** via `iptables` — banned IPs are dropped by the kernel before reaching nginx
- **L7 application-level blocking** via `nginx deny` — fallback layer returning `403 Forbidden`
- **Rate limiting** via `nginx limit_req` (1 req/sec + burst of 5) — soft throttle returning `429 Too Many Requests`
- **Reverse proxy** hiding the real backend IP — attackers can only reach the shield

### 🤖 Automated response

- **Progressive ban escalation:**
  - 1st strike → 24-hour ban
  - 2nd strike → 5-day ban
  - 3rd strike → 30-day ban
- **Automatic unban** when `ban_until` expires — at **both** iptables and nginx layers
- **Strike-counter reset** after 30 days of inactivity (forgives reformed offenders)
- **systemd timer** runs the engine every minute — no manual intervention

### 📊 Monitoring

- **Flask dashboard** on port 5000 showing:
  - Real-time attack statistics
  - Top suspicious IPs with **GeoIP country** lookup
  - Active bans with **countdown timer** until unban
  - Visual progress bar of ban time elapsed
  - Live attack log feed
  - Auto-refresh every 10 seconds
- **Action log** at `/var/log/smart_block.log` with timestamped events

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Cloud** | Google Cloud Platform (3 × Ubuntu 22.04 e2-micro VMs) |
| **Web Server** | Nginx 1.22 (reverse proxy + rate limiting + L7 IP blocking) |
| **Firewall** | iptables (L3/L4 packet filtering) |
| **Automation** | Python 3.10 (log parsing, ban management, state machine) |
| **Scheduling** | systemd timer (minute-level granularity) |
| **Dashboard** | Flask + Bootstrap 5 + matplotlib + ip-api.com (GeoIP) |
| **Testing** | curl, Apache Benchmark (ab), k6 |

---

## 🚀 Quick Start

> Requires a Google Cloud account, three Ubuntu 22.04 VMs in the same VPC, and basic Linux admin knowledge.

### 1. Set up the shield VM

```bash
# Install Nginx
sudo apt update && sudo apt install -y nginx python3-flask iptables-persistent

# Copy nginx configuration
sudo cp nginx_configs/nginx.conf /etc/nginx/nginx.conf
sudo cp nginx_configs/sites-available_default /etc/nginx/sites-available/default
sudo nginx -t && sudo systemctl reload nginx
```

### 2. Deploy smart_block

```bash
# Install the script
sudo mkdir -p /opt/smart_block /var/lib/smart_block
sudo cp v2_improved/smart_block.py /opt/smart_block/
sudo chmod +x /opt/smart_block/smart_block.py

# Enable the systemd timer
sudo cp systemd/smart_block.service /etc/systemd/system/
sudo cp systemd/smart_block.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now smart_block.timer
```

### 3. Run the dashboard

```bash
python3 v2_improved/dashboard.py
# Open http://<shield-public-ip>:5000/ in your browser
```

Full installation guide: [INSTALL.md](INSTALL.md)

---

## 🧪 Test Results

Attack simulation from `vm-attack` against `vm-shield`:

```bash
for i in {1..50}; do curl http://<shield-ip> & done
```

| Metric | Without Shield | With Shield |
|--------|---------------:|------------:|
| Target CPU under attack | **228%** (overloaded) | **< 5%** (stable) |
| Service availability | ❌ Down | ✅ Up |
| Attacker IP blocked | ❌ No | ✅ Yes (L3 + L7) |
| Time to auto-block | n/a | ≤ 60 seconds |
| Time to auto-unban after expiry | n/a | ≤ 60 seconds |

### Sample log output

```
2026-05-26 13:00:01 [INFO]    === smart_block run start ===
2026-05-26 13:00:01 [INFO]    Chain SMART_BLOCK attached to INPUT
2026-05-26 13:00:01 [WARNING] BAN  35.223.216.81  strikes=3  duration=30d 0h
2026-05-26 13:00:01 [WARNING] iptables: DROP added for 35.223.216.81
2026-05-26 13:00:01 [INFO]    nginx blocked_ips.conf updated (1 active bans)
2026-05-26 13:00:01 [INFO]    nginx reloaded
2026-05-26 13:00:01 [INFO]    === Done. Active bans: 1, new: 1 ===
```

---

## 🔄 Post-Review Improvements

After the initial defense, my reviewer raised an important critique:

> *"IP addresses should not remain permanently blocked. The system needs automatic verification — if an address is no longer a threat (e.g., an infected device that has been cleaned), the ban should be lifted automatically."*

This was a valid concern. The original implementation only added entries to `blocked_ips.conf` and never removed them, leading to permanent blocks even for compromised-then-cleaned devices.

### What changed in v2

| Aspect | v1 (original) | v2 (improved) |
|--------|---------------|---------------|
| Blocking layer | nginx only | **iptables (L3/L4) + nginx (L7)** |
| Ban duration | Permanent | **24h → 5d → 30d** (progressive) |
| Auto-unban | None | **Yes, every minute** |
| Strike reset | None | **After 30 days of inactivity** |
| Scheduling | cron | **systemd timer** |
| Logging | None | `/var/log/smart_block.log` |

The improved system respects the **"presumption of innocence"** — compromised devices get a chance to recover without permanent punishment.

Both versions are preserved in this repo: [`v1_original/`](03_Source_Code/v1_original/) and [`v2_improved/`](03_Source_Code/v2_improved/).

---

## 📂 Repository Structure

```
.
├── 03_Source_Code/
│   ├── v1_original/             # Original thesis implementation
│   │   ├── auto_block.py
│   │   ├── dashboard_original.py
│   │   └── README.md
│   ├── v2_improved/             # Post-review improvements
│   │   ├── smart_block.py       # Main blocking engine (iptables + nginx)
│   │   ├── dashboard.py         # Flask monitoring dashboard
│   │   ├── analytics_helper.py  # Reusable helpers (time formatting, etc.)
│   │   └── README.md
│   ├── nginx_configs/
│   │   ├── nginx.conf
│   │   └── sites-available_default
│   └── systemd/
│       ├── smart_block.service
│       └── smart_block.timer
├── 04_Documentation/
│   └── INSTALL.md               # Full installation guide
└── README.md
```

---

## 📚 What I Learned

- **Multi-vhost nginx config gotcha:** Originally, the `deny` rules were inside a single server block but the default nginx server (catching IP-direct requests) was a different block — letting attackers bypass the blocklist via the default server. Fixed by moving the `include /etc/nginx/blocked_ips.conf;` to the http {} context (applies globally).
- **Defense-in-depth is real:** Combining iptables (kernel level) with nginx deny (application level) means even if one layer fails, the other catches the attacker.
- **Auto-unban matters more than you think:** Permanent bans cause false-positive damage. A graceful ban-expiry policy is essential for any system that touches real users.
- **GCP VPC internal routing:** Traffic between VMs in the same VPC short-circuits over internal IPs. This affects which IP nginx sees as `$remote_addr` — a subtle but important detail when configuring rate-limit zones.

---

## 🚧 Limitations & Future Work

This is a **prototype**, not a production-grade DDoS shield. Known limitations:

- **Single point of failure:** Only one shield VM. Production would need multiple shields behind a load balancer + Anycast routing.
- **No Tbps-scale defense:** Real volumetric DDoS requires scrubbing centers (Cloudflare-scale infrastructure).
- **No HTTPS termination yet:** Currently HTTP-only; adding SSL/TLS via Let's Encrypt is the natural next step.
- **Rule-based only:** No machine learning or behavioral analysis to catch sophisticated bots that stay just under the rate limit.
- **No IP rotation defense:** A botnet rotating through 10k IPs at 5 r/s per IP would slip under the current threshold.

### Future directions

- [ ] HTTPS / TLS support with Let's Encrypt
- [ ] ML-based anomaly detection for adaptive attackers
- [ ] Distributed deployment across multiple regions
- [ ] CAPTCHA / JS-challenge for suspicious-but-not-banned traffic
- [ ] Public IP reputation feed integration (AbuseIPDB, etc.)

---

## 📜 License

MIT License — see [LICENSE](LICENSE).

---

## 👤 Author

**Mikael Khangaldyan**
*Junior Cybersecurity Analyst*  •  Yerevan, Armenia

- 📧 khangaldyanm@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/michael-khangaldyan)
- 🐙 [GitHub](https://github.com/MichaelKhangaldyan)

**Certifications:** CISCO Junior Cybersecurity Analyst Career Path (2025)

---

<div align="center">

*If this project helped you, consider starring the repo ⭐*

</div>
