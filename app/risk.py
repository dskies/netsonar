"""
risk.py — Offline device risk / exposure scoring engine for NetSonar.

All scoring is deterministic and requires zero internet access.
Rules are based on:
  - Open ports and their associated protocols / known attack vectors
  - Device role (gateway, IoT, camera, server …)
  - Operating system End-of-Life detection
  - Attack surface (sheer port count)
  - Vendor / model heuristics (devices with known weak firmware)
  - Behavioural / metadata flags (untrusted, no hostname, IPv6 exposure…)

Score → Level mapping:
  CRITICAL   75 – 100
  HIGH       50 – 74
  MEDIUM     25 – 49
  LOW        10 – 24
  MINIMAL     0 – 9
"""

import json
from typing import Optional

# ── Port risk database ─────────────────────────────────────────────────────────
# port → (weight, severity, description)
#   weight: points contributed to final score (before caps)
#   severity: "critical" | "high" | "medium" | "low" | "info"

_PORT_DB: dict[int, tuple[int, str, str]] = {
    # ── Cleartext remote-access shells ────────────────────────────────────────
    23:    (40, "critical", "Telnet — cleartext remote shell, credentials in the clear"),
    2323:  (38, "critical", "Telnet on alternate port — cleartext remote shell"),
    512:   (38, "critical", "rexec — cleartext remote execution (pre-SSH era)"),
    513:   (38, "critical", "rlogin — cleartext remote login"),
    514:   (35, "critical", "rsh — cleartext remote shell"),
    69:    (30, "high",     "TFTP — unauthenticated file transfer, no credentials"),
    # ── Remote desktop / graphical access ─────────────────────────────────────
    5900:  (35, "critical", "VNC — remote desktop (commonly left unauthenticated)"),
    5800:  (30, "high",     "VNC Java web interface"),
    3389:  (30, "high",     "RDP — Remote Desktop Protocol"),
    # ── Web-based admin panels ────────────────────────────────────────────────
    10000: (25, "high",     "Webmin — web-based system administration panel"),
    8834:  (20, "high",     "Nessus — vulnerability scanner administrative interface"),
    9090:  (18, "medium",   "Cockpit / Prometheus — HTTP management interface"),
    8888:  (18, "medium",   "HTTP management interface"),
    9000:  (18, "medium",   "HTTP management / monitoring interface"),
    5601:  (18, "medium",   "Kibana — log-analysis UI exposed on network"),
    4848:  (22, "medium",   "GlassFish application server admin console"),
    7001:  (28, "high",     "Oracle WebLogic — recurring critical CVEs"),
    8161:  (22, "medium",   "Apache ActiveMQ admin console"),
    # ── File sharing / lateral movement ───────────────────────────────────────
    445:   (30, "high",     "SMB — file sharing (EternalBlue / ransomware vector)"),
    139:   (22, "high",     "NetBIOS Session — legacy file sharing"),
    135:   (18, "medium",   "MS-RPC endpoint mapper — broad attack surface"),
    2049:  (25, "high",     "NFS — network file system (often exported without auth)"),
    111:   (18, "medium",   "portmapper / rpcbind — service enumeration"),
    # ── Databases exposed on the network ──────────────────────────────────────
    1433:  (35, "critical", "MSSQL — SQL Server database exposed on LAN"),
    3306:  (35, "critical", "MySQL / MariaDB — database server exposed"),
    5432:  (35, "critical", "PostgreSQL — database server exposed"),
    27017: (40, "critical", "MongoDB — often deployed unauthenticated by default"),
    6379:  (40, "critical", "Redis — in-memory store, no auth by default"),
    9200:  (35, "critical", "Elasticsearch — HTTP API, no auth by default in older versions"),
    11211: (35, "critical", "Memcached — unauthenticated, historical DRDoS amplifier"),
    5984:  (28, "high",     "CouchDB — document database exposed"),
    9042:  (28, "high",     "Cassandra — wide-column database exposed"),
    7474:  (22, "high",     "Neo4j — graph database HTTP interface"),
    1521:  (35, "critical", "Oracle Database — database server exposed"),
    2181:  (20, "medium",   "Zookeeper — coordination service, sensitive cluster data"),
    # ── Container / orchestration ─────────────────────────────────────────────
    2375:  (45, "critical", "Docker daemon API — UNENCRYPTED, full host takeover possible"),
    2376:  (32, "high",     "Docker daemon API over TLS — verify client cert enforcement"),
    6443:  (25, "high",     "Kubernetes API server"),
    2379:  (25, "high",     "etcd — Kubernetes key-value store (cluster secrets)"),
    2380:  (22, "high",     "etcd peer communication"),
    # ── Network management ────────────────────────────────────────────────────
    161:   (25, "high",     "SNMP — default community strings 'public/private' prevalent"),
    162:   (18, "medium",   "SNMP Trap receiver"),
    # ── Mail (cleartext) ──────────────────────────────────────────────────────
    25:    (22, "medium",   "SMTP — check for open relay, check for STARTTLS enforcement"),
    110:   (22, "medium",   "POP3 — cleartext mail retrieval"),
    143:   (18, "medium",   "IMAP — cleartext mail access"),
    # ── Web (unencrypted) ─────────────────────────────────────────────────────
    80:    (10, "low",      "HTTP — unencrypted web interface"),
    8080:  (14, "low",      "HTTP alternate port — unencrypted web interface"),
    8000:  (12, "low",      "HTTP development / app server"),
    3000:  (12, "low",      "HTTP app server (Grafana / Node.js / etc.)"),
    # ── Web (encrypted) ───────────────────────────────────────────────────────
    443:   (2,  "info",     "HTTPS — encrypted web (standard)"),
    8443:  (5,  "info",     "HTTPS alternate port"),
    4443:  (5,  "info",     "HTTPS alternate port"),
    # ── SSH ───────────────────────────────────────────────────────────────────
    22:    (10, "low",      "SSH — remote access (secure protocol, but exposes admin surface)"),
    2222:  (14, "low",      "SSH on non-standard port"),
    8022:  (14, "low",      "SSH on non-standard port"),
    # ── FTP ───────────────────────────────────────────────────────────────────
    21:    (35, "critical", "FTP — cleartext credentials, active/passive traversal"),
    990:   (10, "low",      "FTPS — FTP over TLS (verify certificate)"),
    # ── DNS ───────────────────────────────────────────────────────────────────
    53:    (5,  "info",     "DNS — resolver or authoritative server"),
    # ── IoT / embedded ────────────────────────────────────────────────────────
    5555:  (40, "critical", "ADB (Android Debug Bridge) — full device shell over network"),
    1883:  (25, "high",     "MQTT broker — no authentication by default in most deployments"),
    8883:  (10, "low",      "MQTT over TLS"),
    5683:  (18, "medium",   "CoAP — constrained IoT protocol"),
    554:   (20, "medium",   "RTSP — streaming server (camera/NVR feed potentially exposed)"),
    # ── DVR / NVR known-vulnerable ports ──────────────────────────────────────
    37777: (28, "high",     "Dahua DVR management — multiple known critical CVEs"),
    37778: (22, "high",     "Dahua DVR media streaming port"),
    34567: (30, "high",     "HiSilicon DVR/NVR — exploited in Mirai and successors"),
    8899:  (22, "high",     "Generic DVR/NVR management interface"),
    9527:  (20, "medium",   "Generic DVR/NVR management interface"),
    # ── Home automation ───────────────────────────────────────────────────────
    8123:  (15, "low",      "Home Assistant web interface"),
    1400:  (18, "medium",   "Sonos / UPnP device control"),
    # ── Message queues ────────────────────────────────────────────────────────
    61616: (22, "medium",   "Apache ActiveMQ broker — message queue service"),
    5672:  (18, "medium",   "AMQP (RabbitMQ) — message broker"),
    15672: (20, "medium",   "RabbitMQ management HTTP interface"),
}

# ── Role risk database ─────────────────────────────────────────────────────────
# role_key (uppercase) → (weight, severity, description)

_ROLE_DB: dict[str, tuple[int, str, str]] = {
    "GATEWAY/ROUTER":   (30, "critical", "Network gateway — full LAN-wide compromise on takeover"),
    "NAS":              (22, "high",     "Network-attached storage — data-at-rest exposure, ransomware prime target"),
    "CAMERA/NVR":       (22, "high",     "Surveillance device — firmware rarely patched, default credentials common"),
    "IOT DEVICE":       (20, "high",     "IoT device — firmware update cycle typically poor"),
    "SMART HUB":        (18, "high",     "Smart-home hub — controls IoT ecosystem, pivoting risk"),
    "SERVER":           (15, "medium",   "Server — critical infrastructure node"),
    "SMART THERMOSTAT": (14, "medium",   "Smart thermostat — IoT pivot point"),
    "SMART SPEAKER":    (14, "medium",   "Smart speaker — always-on microphone, IoT attack surface"),
    "DNS SERVER":       (14, "medium",   "DNS server — name-resolution infrastructure, poisoning target"),
    "NETWORK DEVICE":   (12, "medium",   "Network device — infrastructure component"),
    "PRINTER":          (10, "low",      "Printer — print-job interception, stored-document exposure"),
    "MEDIA SERVER":     (10, "low",      "Media server — potential content exposure"),
    "PC/WORKSTATION":   (8,  "low",      "Workstation — user endpoint"),
    "PHONE/TABLET":     (6,  "low",      "Mobile device"),
    "MEDIA PLAYER":     (4,  "info",     "Media player"),
    "THIS HOST":        (0,  "info",     "Local NetSonar scanner host"),
}

# ── End-of-Life OS detection ───────────────────────────────────────────────────
# (lowercase pattern, weight, severity, description)

_EOL_OS: list[tuple[str, int, str, str]] = [
    ("windows xp",            45, "critical", "Windows XP — EoL since Apr 2014, no security patches"),
    ("windows vista",         40, "critical", "Windows Vista — EoL since Apr 2017, no security patches"),
    ("windows 7",             38, "critical", "Windows 7 — EoL since Jan 2020, no security patches"),
    ("windows 2000",          45, "critical", "Windows 2000 — EoL since Jul 2010"),
    ("windows server 2003",   45, "critical", "Windows Server 2003 — EoL since Jul 2015"),
    ("windows server 2008",   35, "critical", "Windows Server 2008 — EoL since Jan 2020"),
    ("windows server 2012",   22, "high",     "Windows Server 2012 — EoL since Oct 2023"),
    ("windows 8.1",           22, "high",     "Windows 8.1 — EoL since Jan 2023"),
    ("windows 8",             28, "high",     "Windows 8 — EoL since Jan 2016"),
    ("linux 2.",              20, "high",     "Linux kernel 2.x — unsupported, likely unpatched vulnerabilities"),
    ("linux 3.",              10, "medium",   "Linux kernel 3.x — out-of-support upstream"),
    ("uclinux",               18, "high",     "uClinux — embedded Linux derivative, rarely updated"),
    ("vxworks",               15, "medium",   "VxWorks RTOS — limited patch lifecycle on embedded hardware"),
    ("embedded",              12, "medium",   "Embedded OS — firmware update cadence typically low"),
    ("openwrt 1",             15, "medium",   "OpenWrt 1x.x — legacy firmware branch"),
]

# ── Vendor / model heuristics ─────────────────────────────────────────────────
# (lowercase pattern, weight, description)

_VENDOR_HINTS: list[tuple[str, int, str]] = [
    ("hikvision",   18, "Hikvision — multiple critical CVEs in NVR/DVR firmware"),
    ("dahua",       18, "Dahua — multiple critical CVEs in NVR/DVR firmware"),
    ("foscam",      18, "Foscam — historically weak default credentials"),
    ("axis",        10, "Axis Communications camera — verify firmware version"),
    ("tp-link",      8, "TP-Link consumer device — verify firmware is current"),
    ("d-link",       8, "D-Link consumer device — verify firmware is current"),
    ("netgear",      8, "Netgear consumer device — recurring firmware CVEs"),
    ("zyxel",        8, "Zyxel — recent critical CVEs in VPN/gateway products"),
    ("mikrotik",    10, "MikroTik — RouterOS has historical CVEs; verify version"),
    ("siemens",     10, "Siemens — OT/ICS device, critical infrastructure classification"),
    ("schneider",   10, "Schneider Electric — OT/ICS device, critical infrastructure"),
    ("rockwell",    10, "Rockwell Automation — OT/ICS industrial device"),
    ("esp8266",     15, "ESP8266 — bare IoT module, minimal security model"),
    ("esp32",       12, "ESP32 — IoT module, minimal security model"),
    ("arduino",     12, "Arduino — microcontroller, no OS security model"),
    ("raspberry",    5, "Raspberry Pi — verify OS is hardened and updated"),
    ("ubiquiti",     6, "Ubiquiti — verify UniFi Controller / firmware version"),
]


# ── Public scoring function ────────────────────────────────────────────────────

def score_device(
    mac: Optional[str],
    last_ip: Optional[str],
    last_hostname: Optional[str],
    alias: Optional[str],
    last_ports_json: Optional[str],
    last_os: Optional[str],
    last_vendor: Optional[str],
    last_model: Optional[str],
    last_services_json: Optional[str],
    role: Optional[str],
    is_trusted: bool,
) -> dict:
    """
    Compute an offline risk score and return a structured result dict.

    Returns:
        {
            "score":            int,          # 0–100
            "level":            str,          # CRITICAL | HIGH | MEDIUM | LOW | MINIMAL
            "level_color":      str,          # CSS var
            "findings":         list[dict],   # sorted by weight desc
            "category_scores":  dict,
        }
    """
    findings: list[dict] = []
    cat_ports   = 0
    cat_role    = 0
    cat_os      = 0
    cat_surface = 0
    cat_flags   = 0

    # ── 1. Port-based risk ─────────────────────────────────────────────────
    try:
        ports: list[dict] = json.loads(last_ports_json) if last_ports_json else []
    except (json.JSONDecodeError, TypeError):
        ports = []

    for p in ports:
        pnum = int(p.get("port", 0))
        if pnum in _PORT_DB:
            pts, sev, desc = _PORT_DB[pnum]
            findings.append({
                "severity": sev,
                "text": f"Port {pnum}/{'tcp' if p.get('proto','tcp')=='tcp' else p.get('proto','tcp')} open — {desc}",
                "port": pnum,
                "weight": pts,
            })
            cat_ports += pts

    cat_ports = min(cat_ports, 60)

    # ── 2. Role-based risk ─────────────────────────────────────────────────
    eff_role = (role or "Host").upper().strip()
    role_matched = False
    for rkey, (pts, sev, desc) in _ROLE_DB.items():
        if rkey == eff_role:
            if pts > 0:
                findings.append({
                    "severity": sev,
                    "text": f"Role [{rkey}] — {desc}",
                    "port": None,
                    "weight": pts,
                })
            cat_role = pts
            role_matched = True
            break
    if not role_matched and eff_role not in ("HOST", ""):
        # Unknown role — treat as generic host
        cat_role = 5

    # ── 3. OS / End-of-Life detection ─────────────────────────────────────
    if last_os:
        ogl = last_os.lower()
        for pattern, pts, sev, desc in _EOL_OS:
            if pattern in ogl:
                findings.append({
                    "severity": sev,
                    "text": desc,
                    "port": None,
                    "weight": pts,
                })
                cat_os += pts
                break  # one EOL hit is enough per device

    cat_os = min(cat_os, 45)

    # ── 4. Attack surface (sheer port count) ──────────────────────────────
    port_count = len(ports)
    if port_count > 20:
        findings.append({
            "severity": "high",
            "text": f"Extreme attack surface — {port_count} open ports detected",
            "port": None,
            "weight": 20,
        })
        cat_surface = 20
    elif port_count > 10:
        findings.append({
            "severity": "medium",
            "text": f"Large attack surface — {port_count} open ports detected",
            "port": None,
            "weight": 14,
        })
        cat_surface = 14
    elif port_count > 5:
        findings.append({
            "severity": "low",
            "text": f"Moderate attack surface — {port_count} open ports detected",
            "port": None,
            "weight": 8,
        })
        cat_surface = 8

    # ── 5. Vendor / model heuristics ──────────────────────────────────────
    vendor_str = ((last_vendor or "") + " " + (last_model or "")).lower()
    for vpattern, pts, vdesc in _VENDOR_HINTS:
        if vpattern in vendor_str:
            findings.append({
                "severity": "medium",
                "text": f"Vendor advisory — {vdesc}",
                "port": None,
                "weight": pts,
            })
            cat_flags += pts
            break  # one vendor hit per device

    # ── 6. Behavioural / metadata flags ───────────────────────────────────
    if not is_trusted:
        findings.append({
            "severity": "info",
            "text": "Device not marked as trusted in the device registry",
            "port": None,
            "weight": 5,
        })
        cat_flags += 5

    if not last_hostname or last_hostname.lower() in ("n/a", "none", "unknown", ""):
        findings.append({
            "severity": "info",
            "text": "No hostname resolved — unidentified device on LAN",
            "port": None,
            "weight": 4,
        })
        cat_flags += 4

    if last_ip and ":" in last_ip:
        findings.append({
            "severity": "info",
            "text": "IPv6 primary address — verify firewall rules also cover IPv6",
            "port": None,
            "weight": 3,
        })
        cat_flags += 3

    cat_flags = min(cat_flags, 20)

    # ── Total & level ──────────────────────────────────────────────────────
    score = min(cat_ports + cat_role + cat_os + cat_surface + cat_flags, 100)
    findings.sort(key=lambda f: f["weight"], reverse=True)

    return {
        "score": score,
        "level": _level(score),
        "level_color": _level_color(score),
        "findings": findings,
        "category_scores": {
            "ports":   cat_ports,
            "role":    cat_role,
            "os":      cat_os,
            "surface": cat_surface,
            "flags":   cat_flags,
        },
    }


def _level(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 50: return "HIGH"
    if score >= 25: return "MEDIUM"
    if score >= 10: return "LOW"
    return "MINIMAL"


def _level_color(score: int) -> str:
    if score >= 75: return "var(--red)"
    if score >= 50: return "var(--amber)"
    if score >= 25: return "#e8c044"
    if score >= 10: return "var(--green2)"
    return "var(--textdim)"
