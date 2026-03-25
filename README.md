# NetSonar

**Self-hosted LAN monitoring tool with device tracking, port scanning, risk assessment, and change notifications. No internet required.**

NetSonar continuously scans your local network, maintains a persistent device registry, detects topology changes, assesses the security exposure of every known host, and delivers notifications when something unexpected appears or disappears — all from a single Docker container, entirely offline.

---

## Features

| Tab | What it does |
|---|---|
| **Live Scan** | Real-time scan progress via Server-Sent Events. Hosts appear as they are discovered; ports fill in as each device is probed. |
| **History** | Browsable archive of every past scan. Filter by subnet, sort by host count or time, drill into any scan's full device list. |
| **Devices** | Persistent device registry keyed by MAC address. Assign aliases, notes, and a "trusted" flag. Tracks first/last seen, IP history, OS, vendor, open ports, and services. |
| **Notifications** | Timestamped event log of all notable changes: new device, device disappeared, device reappeared, port set changed. |
| **Risk** | Offline security exposure score (0–100) for every known device. Considers open ports, device role, OS end-of-life status, attack surface, vendor heuristics, and behavioural flags. Two-column grid with SVG gauges. |
| **Graph** | Scan history visualisations: RTT sparklines, topology summary, service distribution, per-device heuristics — loaded lazily with IntersectionObserver. |
| **Compare** | Side-by-side diff between any two scans: new hosts, gone hosts, port changes. |

### Scanner capabilities

- **Network discovery**: `nmap -sn` ping sweep across all local subnets (auto-detected from `ip route`)
- **Port scan**: Two-phase approach — Phase A: fast SYN scan all 65 535 ports; Phase B: `-sV` service version detection only on discovered open ports
- **OS detection**: nmap OS fingerprinting
- **mDNS / Bonjour**: Pure-Python UDP multicast — discovers Apple, Chromecast, printers, smart-home devices without requiring Avahi on the host (optional Avahi socket mount improves results)
- **UPnP / SSDP**: UDP 1900 M-SEARCH — extracts device name, model, and manufacturer from UPnP XML
- **WSD**: UDP 3702 — discovers Windows workstations
- **SNMP**: Optional community-string walk of the gateway ARP table for additional MAC→IP mappings
- **DHCP lease parsing**: reads `/var/lib/dhcp/dhclient.leases` to tag the DHCP server
- **ARP table**: `/proc/net/arp` and `arp -an` for passive MAC resolution
- **Role detection**: automatic classification (GATEWAY/ROUTER, DNS SERVER, THIS HOST, NAS, Printer, IoT, …)

---

## Requirements

- **Docker** and **Docker Compose** v2+ on the host
- Host must have `network_mode: host` support (Linux — standard; macOS/Windows Docker Desktop does **not** support this)
- For best mDNS results: `avahi-daemon` running on the host (optional)

---

## Quick Start (online build)

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/netsonar.git
cd netsonar

# 2. Edit docker-compose.yml — set your timezone and optional SMTP config (see below)

# 3. Build and run
docker compose up -d --build

# 4. Open browser
http://<server-ip>:7979
```

The first time Docker builds the image it will download nmap, net-snmp, avahi-tools, and all Python dependencies from the internet.

---

## Offline / Air-gapped Deployment

NetSonar supports fully offline deployment — useful for isolated networks with no internet access.

### Step 1 — Download packages (on a Windows machine with internet)

```powershell
.\prepare-offline.ps1
```

This script:
- Fetches all required Alpine `.apk` packages (nmap, net-snmp, avahi, dbus, and all their dependencies) from the Alpine CDN
- Downloads all Python wheels for `linux/amd64` (musl) from PyPI
- Saves everything to `packages/apk/` and `packages/wheels/`

### Step 2 — Transfer to the server

```bash
scp -r netsonar/ user@192.168.x.x:/opt/netsonar
```

### Step 3 — Build and run (no internet needed)

```bash
cd /opt/netsonar
docker compose up -d --build
```

The Dockerfile detects whether package files are present and switches between offline (local files) and online (CDN/PyPI) installation automatically.

> **Note:** `packages/apk/` and `packages/wheels/` are excluded from git by `.gitignore`. You must run `prepare-offline.ps1` before deploying to an air-gapped host.

---

## Configuration

All settings are passed as environment variables in `docker-compose.yml`:

### Scanner

| Variable | Default | Description |
|---|---|---|
| `SCAN_INTERVAL_MINUTES` | `60` | How often to auto-scan. Set to `0` to disable automatic scanning (manual-only mode). |
| `SCAN_TIMEOUT_MS` | `500` | Per-host ping timeout in milliseconds. Increase on slow or congested networks. |
| `NMAP_EXTRA_ARGS` | *(empty)* | Extra flags appended to every nmap invocation (e.g. `--min-rate 2000`). |

### SNMP

| Variable | Default | Description |
|---|---|---|
| `SNMP_COMMUNITY` | `public` | SNMPv2c community string for ARP table walk on the gateway. |

### Notifications (Email via SMTP)

| Variable | Default | Description |
|---|---|---|
| `NOTIFY_ENABLED` | `false` | Set to `true` to enable email notifications. |
| `SMTP_HOST` | *(empty)* | SMTP server hostname (e.g. `smtp.gmail.com`). |
| `SMTP_PORT` | `587` | SMTP port. Use `587` for STARTTLS, `465` for SSL. |
| `SMTP_USER` | *(empty)* | SMTP login username. |
| `SMTP_PASS` | *(empty)* | SMTP password or app-specific password. |
| `NOTIFY_FROM` | *(empty)* | Sender address shown in the email. Defaults to `SMTP_USER` if unset. |
| `NOTIFY_TO` | *(empty)* | Recipient address for all alert emails. |

Email notifications are sent via [Apprise](https://github.com/caronc/apprise) and fire for:
- **New device** — a MAC address never seen before
- **Device disappeared** — was present in the previous scan, absent in the current
- **Device reappeared** — previously disappeared, now visible again
- **Port change** — open port set changed since last scan
- **Scan summary** — only when at least one notable event occurred

### App

| Variable | Default | Description |
|---|---|---|
| `DB_PATH` | `/data/netsonar.db` | Path to the SQLite database inside the container. |
| `PORT` | `7979` | TCP port uvicorn listens on. |
| `TZ` | `Europe/London` | Container timezone (affects timestamps in logs and UI). |

---

## Risk Scoring

The **Risk** tab computes an offline exposure score (0–100) for each known device using a deterministic rule engine in `risk.py`. No internet connection is ever required.

### Score categories

| Category | Max contribution | What it measures |
|---|---|---|
| **Ports** | 60 pts | Each open port contributes weighted points based on the associated protocol risk (Telnet=40, Docker API=45, Redis=40, SMB=30, …) |
| **Role** | 30 pts | Device role risk weight (IoT=20, NAS=22, Gateway=30, Security camera=28, …) |
| **OS / EoL** | 45 pts | Detected OS matched against an end-of-life list (Windows XP=45, Win 7=38, Linux 2.x=15, …) |
| **Surface** | 20 pts | Raw port count above thresholds (>5 ports = moderate, >20 = extreme) |
| **Flags** | 20 pts | Metadata flags: not trusted in registry, no hostname, generic vendor, IPv6 exposure |

Total score is capped at 100.

### Risk levels

| Level | Score range | Colour |
|---|---|---|
| CRITICAL | 75 – 100 | Red |
| HIGH | 50 – 74 | Amber |
| MEDIUM | 25 – 49 | Yellow |
| LOW | 10 – 24 | Green |
| MINIMAL | 0 – 9 | Grey |

### Network Exposure Score

The summary banner shows an aggregate **Network Exposure Score** (0–100), computed as a weighted average skewed toward the highest-risk devices: the top-3 devices contribute 60% of the total, the rest contribute 40%.

---

## API Reference

All endpoints are under `/api/`. A Swagger UI is available at `/api/docs`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | App status: scan running, last scan summary, next scheduled time, unread notification count |
| `POST` | `/api/scan` | Trigger an immediate scan |
| `GET` | `/api/scan/stream` | Server-Sent Events stream — live scan progress (host_ping_done, port_scan_start, host_done, done) |
| `GET` | `/api/scans` | Paginated list of past scans (`page`, `per_page` ≤ 100) |
| `GET` | `/api/scans/{id}` | Single scan with full device list |
| `GET` | `/api/scans/{id}/devices` | Devices of a scan (paginated, filterable by `subnet`) |
| `GET` | `/api/scans/diff/{id_a}/{id_b}` | Structural diff between two scans |
| `GET` | `/api/devices` | Known device registry (paginated) |
| `PATCH` | `/api/devices/{mac}` | Update `alias`, `notes`, `is_trusted`, `role_override` |
| `GET` | `/api/risk` | Offline risk scores for all known devices + network summary |
| `GET` | `/api/notifications` | Event log (`page`, `per_page`, `event_type` filter) |
| `GET` | `/api/config` | Active configuration (non-secret fields only) |

---

## Project Structure

```
netsonar/
├── Dockerfile                  ← Alpine-based image, supports online & offline builds
├── docker-compose.yml          ← Deployment configuration
├── prepare-offline.ps1         ← Windows script to pre-download packages for air-gapped deploy
├── README.md
├── .gitignore
│
├── data/                       ← Created at runtime; contains netsonar.db (gitignored)
│
├── packages/                   ← Populated by prepare-offline.ps1 (gitignored)
│   ├── apk/                    ← Alpine .apk packages
│   └── wheels/                 ← Python .whl packages
│
└── app/
    ├── main.py                 ← FastAPI application, all API routes
    ├── scanner.py              ← Network scanner (nmap, mDNS, UPnP, WSD, SNMP, ARP)
    ├── scheduler.py            ← APScheduler, DB persistence, change detection
    ├── notifier.py             ← Email notifications via Apprise
    ├── models.py               ← SQLAlchemy ORM models (SQLite)
    ├── config.py               ← Environment variable configuration
    ├── risk.py                 ← Offline risk scoring engine
    └── static/
        ├── index.html          ← Single-page application shell
        ├── app.js              ← All frontend logic (vanilla JS, no framework)
        └── style.css           ← Terminal-style UI (green-on-black)
```

### Database schema

| Table | Description |
|---|---|
| `scans` | One row per scan run (status, timing, subnet list, host count) |
| `scan_devices` | Every device found in each scan (IP, MAC, ports JSON, OS, vendor, services) |
| `known_devices` | Persistent device registry — survives across scans; holds aliases, notes, trusted flag |
| `device_rtt_history` | RTT and up/down timeseries per MAC per scan — drives latency sparklines |
| `device_events` | Audit log of new/disappeared/reappeared/ports_changed events |

---

## Security Notes

- NetSonar is intended for **isolated LANs only**. Do not expose the web interface to the internet.
- `network_mode: host` and `cap_add: NET_RAW, NET_ADMIN` grant the container elevated network privileges — required for nmap ARP scans and OS fingerprinting.
- All SMTP credentials are supplied via environment variables and never stored in the database.
- The risk scoring engine is fully deterministic and offline — no telemetry, no external calls.
- The SQLite database (`data/netsonar.db`) may contain sensitive information about your network topology. Protect the `data/` directory accordingly.

---

## Tech Stack

- **Backend**: [FastAPI](https://fastapi.tiangolo.com/) + [SQLAlchemy](https://www.sqlalchemy.org/) + [APScheduler](https://apscheduler.readthedocs.io/) + [Apprise](https://github.com/caronc/apprise)
- **Scanner**: nmap, net-snmp, avahi-tools (all bundled in Docker image)
- **Database**: SQLite (zero-dependency, single file)
- **Frontend**: Vanilla JavaScript SPA — no framework, no build step
- **Runtime**: Python 3.12 on Alpine Linux

---

## License

MIT — see [LICENSE](LICENSE) for details.

