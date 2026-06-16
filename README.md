# Mirror Trap

## An attacker hits port 22 on your server at 3:14 AM.

Your phone buzzes. Telegram lights up:

```
🔴 NEW ATTACK DETECTED
IP: 185.220.101.156
Port: 22 (SSH)
Classification: Script Kiddie
Confidence: 87%
```

You open the dashboard. You see their keystrokes in real time — `root` / `admin123`, `admin` / `password`, then they try a known CVE exploit. The honeypot feeds them a fake network. Routers, databases, admin panels — all fake, all recording. They spend 11 minutes inside your imaginary infrastructure. You watch every move.

They never touch a real machine. You walk away with their tool signatures, their credential lists, their IP rotation pattern — all saved to your growing attacker database.

**That's Mirror Trap.**

A self-hosted, multi-port honeypot that listens on 8 real TCP ports, logs attacker activity, classifies threats via AI, and alerts you over Telegram in real time — before they ever touch production.

> *When attackers come, make sure they're talking to furniture.*

---

## Features

- **8-port listener** — SSH (22), HTTP (80), HTTPS (443), MySQL (3306), PostgreSQL (5432), Redis (6379), HTTP-Alt (8080), HTTPS-Alt (8443)
- **Rabbit Hole** — Multi-layer fake environments that look real. Attackers connect to what they think is a live server and spend minutes exploring a simulation
- **AI classification** — Each attacker is analyzed by DeepSeek LLM: script kiddie, APT, recon crawler, credential stuffer — with confidence score
- **Telegram alerts** — Instant notification with IP, port, classification, and timestamp
- **Live dashboard** — Real-time socket stream of every connection, keystroke, and credential attempted
- **Attack DNA** — Behavioral fingerprinting (TCP window, TTL, banners, command order). Re-identify the same attacker through different IPs
- **Slow poison** — Deters scrapers and crawlers by serving responses at 1 byte/second
- **Adversarial noise** — Fake configs, databases, and credentials flood attacker output with noise
- **PDF threat reports** — One-click export with charts, top IPs, and classification breakdown
- **Dark/light theme** — ☯ toggle in the dashboard header

---

## Demo (30 seconds)

```bash
git clone https://github.com/ApnexQQQ/mirror-trap.git
cd mirror-trap
pip install -r requirements.txt
python3 main.py &
cd dashboard && python3 app.py
```

Open `http://localhost:5000` — live dashboard. Hit one of the ports from another machine. Watch the alert come in on Telegram.

---

## Quick Start

### Requirements

- Python 3.10+
- Linux (tested on Ubuntu 24.04/26.04, WSL2)
- Systemd (optional — for auto-restart)

### Install & Run

```bash
git clone https://github.com/ApnexQQQ/mirror-trap.git
cd mirror-trap
pip install -r requirements.txt

# Set up Telegram
cp .env.example .env
# Edit .env → add your bot token and chat ID

# Start the honeypot
python3 main.py

# Start the dashboard (separate terminal)
cd dashboard && python3 app.py
```

Open `http://localhost:5000` — you're live.

### Systemd (auto-restart on crash)

```bash
sudo cp liarsecho-honeypot.service /etc/systemd/system/
sudo cp liarsecho-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mirrortrap-honeypot
sudo systemctl enable --now mirrortrap-dashboard
```

---

## Architecture

```
liars_echo/
├── main.py                      # Entry point — starts honeypot listeners
├── config/
│   └── settings.py              # DB path, ports, credentials
├── core/
│   └── detector.py              # Attack detection engine
├── modules/
│   ├── rabbit_hole.py           # Multi-layer fake environment
│   ├── classifier.py            # AI threat classification (DeepSeek)
│   ├── alerting.py              # Telegram alert dispatcher
│   ├── dna_db.py                # Attack fingerprint database
│   ├── fake_topology.py         # Fake network topology generator
│   ├── self_learning.py         # Adaptive learning from attack patterns
│   ├── slow_poison.py           # Slow-respond poisoning for scrapers
│   ├── adversarial_noise.py     # Noise injection into fake services
│   └── pdf_report.py            # PDF threat report generator
├── dashboard/
│   ├── app.py                   # Flask + Socket.IO server
│   └── static/
│       ├── dashboard.html       # Main monitoring UI
│       ├── admin.html           # Admin panel
│       └── login.html           # Login page
├── data/
│   ├── fingerprints.db          # SQLite database
│   └── liars_echo.log           # Application log
├── Dockerfile
├── docker-compose.yml
├── liarsecho-honeypot.service
└── liarsecho-dashboard.service
```

---

## How It Works

1. **Listen** — 8 TCP ports run fake services that respond like the real thing (SSH banner, HTTP 200, MySQL handshake)
2. **Capture** — Rabbit Hole presents fake login prompts, command shells, and databases. Every keystroke is logged
3. **Classify** — The AI classifier analyzes attack patterns and assigns a threat type with confidence
4. **Alert** — Telegram delivers a formatted alert in under 2 seconds
5. **Log** — Every session is written to SQLite with full replay data
6. **Monitor** — The dashboard streams everything in real time via WebSocket

---

## Dashboard

Self-contained single-page app. All CSS/JS inline — no CDN, no external dependencies.

**Features:**
- Real-time attack counter + rate (attacks/min)
- Threat type distribution gauge
- Top attacker IPs with flag/country
- Live session log with per-session detail
- Attack timeline chart
- Connection status indicator
- Dark/light toggle ☯
- PDF export (24h / 7d / 30d)

---

## Telegram Alerts

```
🔴 NEW ATTACK DETECTED
IP: 185.220.101.x
Port: 22 (SSH)
Protocol: TCP
Time: 2026-06-13 14:32:18
Classification: Script Kiddie
Confidence: 87%
```

Setup:
1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
3. Add to `.env`: `TELEGRAM_BOT_TOKEN=...` and `TELEGRAM_CHAT_ID=...`

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `DB_PATH` | `~/liars_echo/data/fingerprints.db` | SQLite database path |
| `LOG_PATH` | `~/liars_echo/data/liars_echo.log` | Log file path |
| `PORTS` | `[22,80,443,3306,5432,6379,8080,8443]` | Ports to listen on |
| `TELEGRAM_BOT_TOKEN` | from `.env` | Telegram bot token |
| `TELEGRAM_CHAT_ID` | from `.env` | Telegram chat ID |
| `DASHBOARD_PASSWORD` | `liarsecho123` | Dashboard login |
| `DEEPSEEK_API_KEY` | from `.env` | AI classification key |

---

## Docker

```bash
docker compose up -d
```

---

## Security Notes

- Running a honeypot exposes real ports — use on isolated or monitored networks
- Change the default `DASHBOARD_PASSWORD` before exposing to the internet
- Use Tailscale Funnel or a reverse proxy for secure remote access
- `.env` is in `.gitignore` — credentials never committed

---

## License

**BUSL 1.1** — Code is publicly visible. Commercial use (SaaS, white-label, managed service) requires permission.

For commercial licensing: **apnexqqq@protonmail.com**

---

## Built With

Python, Flask, Socket.IO, SQLite. Threat classification by DeepSeek LLM.
