"""
scanner.py — nmap-based LAN scanner

Flow:
  1. Read all local interfaces with their CIDRs (via `ip route`); skip virtual/container ifaces
  2. Pre-collect enrichment data in parallel:
       - ARP table, DHCP leases
       - mDNS/Bonjour via pure-Python UDP multicast (hostname + service type + model)
       - UPnP/SSDP via UDP 1900 M-SEARCH (device name, model, manufacturer)
       - WSD via UDP 3702 (Windows devices)
  3. For each subnet: run nmap -sn (ping sweep) → collect live hosts
  4. Enrich each host from pre-collected data
  5. Two-phase port scan (parallel, up to PORT_SCAN_CONCURRENCY hosts at once):
       Phase A — fast SYN scan all 65535 ports (no -sV), collect open port list
       Phase B — -sV only on open ports found + enrichment scripts
  6. SNMP enrichment (best-effort, parallel with port scan)
  7. Return structured list of DeviceResult objects
"""

import asyncio
import glob
import ipaddress
import json
import logging
import os
import re
import select
import socket
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from config import config

# Max concurrent port scans — tune up/down based on target network size
PORT_SCAN_CONCURRENCY = 5

log = logging.getLogger("scanner")

# SSE broadcast queue — populated during scan, consumed by /api/scan/stream
_sse_queue: asyncio.Queue = asyncio.Queue()

# Partial scan state — allows a page reload to fully restore the live table.
# _partial_devices  : host_done events (port scan finished)
# _partial_ping     : host_ping_done events not yet superseded by host_done
# _scanning_ips     : IPs currently between port_scan_start and host_done
_partial_devices: list[dict] = []
_partial_ping: dict[str, dict] = {}   # ip -> host_ping_done payload
_scanning_ips: set[str] = set()


def get_partial_devices() -> dict:
    return {
        "devices":      list(_partial_devices),
        "ping_devices": list(_partial_ping.values()),
        "scanning_ips": list(_scanning_ips),
    }


async def sse_emit(msg: dict) -> None:
    t = msg.get("type")
    ip = msg.get("ip")
    if t == "host_ping_done" and ip:
        _partial_ping[ip] = msg
    elif t == "port_scan_start" and ip:
        _scanning_ips.add(ip)
    elif t == "port_scan_progress" and ip:
        pass  # phase transition — ip already in _scanning_ips
    elif t == "host_done" and ip:
        _partial_devices.append(msg)
        _partial_ping.pop(ip, None)
        _scanning_ips.discard(ip)
    await _sse_queue.put(msg)


async def sse_stream():
    """Async generator for Server-Sent Events."""
    while True:
        msg = await _sse_queue.get()
        yield msg
        if msg.get("type") == "done" or msg.get("type") == "error":
            break


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    port: int
    proto: str
    state: str
    service: str
    version: str = ""


@dataclass
class DeviceResult:
    ip: str
    subnet: str
    iface: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: Optional[float] = None
    role: str = "Host"
    ports: list[PortInfo] = field(default_factory=list)
    os_guess: Optional[str] = None
    vendor: Optional[str] = None
    # Enrichment from UPnP/mDNS/WSD
    model: Optional[str] = None          # device model (UPnP modelName / mDNS txt)
    services: list[str] = field(default_factory=list)  # ["_airplay._tcp", "upnp:MediaRenderer", …]
    tags: list[str] = field(default_factory=list)       # ["DNS1", "DNS2", "DHCP"]


# ── Network role detection (DNS / DHCP) ─────────────────────────────────────

def _detect_dhcp_server_ip() -> Optional[str]:
    """Best-effort detection of the DHCP server IP from common lease file locations."""
    # dhclient: option dhcp-server-identifier X.X.X.X;
    for path in [
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhclient/dhclient.leases",
    ] + glob.glob("/var/lib/dhcp/dhclient.*.leases"):
        try:
            with open(path) as f:
                content = f.read()
            m = re.search(r'option\s+dhcp-server-identifier\s+([\d.]+)', content)
            if m:
                return m.group(1)
        except OSError:
            pass

    # systemd-networkd: SERVER_ADDRESS=X.X.X.X
    for lease_dir in ("/run/systemd/network/leases", "/run/systemd/netif/leases"):
        try:
            for fname in os.listdir(lease_dir):
                try:
                    with open(os.path.join(lease_dir, fname)) as f:
                        for line in f:
                            m = re.match(r'SERVER_ADDRESS=([\d.]+)', line)
                            if m:
                                return m.group(1)
                except OSError:
                    pass
        except OSError:
            pass

    # dhcpcd: DHCPSERVER= or dhcp_server_identifier=
    for path in glob.glob("/var/lib/dhcpcd/*.lease") + glob.glob("/var/lib/dhcpcd/dhcpcd-*.info"):
        try:
            with open(path) as f:
                for line in f:
                    m = re.match(r'(?:DHCPSERVER|dhcp_server_identifier)=([\d.]+)', line)
                    if m:
                        return m.group(1)
        except OSError:
            pass

    # NetworkManager via nmcli
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "DHCP4", "con", "show", "--active"],
            stderr=subprocess.DEVNULL, timeout=3, text=True,
        )
        m = re.search(r'server_id\s*=\s*([\d.]+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass

    # Final fallback: the default gateway is the DHCP server on virtually all
    # home/office LANs. Also the only reliable option inside a Docker container
    # (network_mode: host shares the network stack but NOT the host filesystem).
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL, timeout=3, text=True,
        )
        m = re.search(r'default via ([\d.]+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass

    return None


def _detect_dhcp_dns_servers() -> list[str]:
    """
    Extract the DNS server list supplied by the DHCP server from lease files.
    Returns up to 2 IPs in order (DNS1, DNS2).
    Tries dhclient → systemd-networkd → dhcpcd → nmcli.
    """
    # dhclient: option domain-name-servers A, B, C;
    for path in [
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhclient/dhclient.leases",
    ] + glob.glob("/var/lib/dhcp/dhclient.*.leases"):
        try:
            with open(path) as f:
                content = f.read()
            # Use the last lease block (most recent)
            blocks = re.findall(r'lease\s*\{([^}]+)\}', content, re.DOTALL)
            for block in reversed(blocks):
                m = re.search(r'option\s+domain-name-servers\s+([\d.,\s]+);', block)
                if m:
                    ips = [s.strip() for s in m.group(1).split(',') if s.strip()]
                    if ips:
                        return ips[:2]
        except OSError:
            pass

    # systemd-networkd: DNS=A B C  (space-separated)
    for lease_dir in ("/run/systemd/network/leases", "/run/systemd/netif/leases"):
        try:
            for fname in sorted(os.listdir(lease_dir)):
                try:
                    with open(os.path.join(lease_dir, fname)) as f:
                        for line in f:
                            m = re.match(r'DNS=(.*)', line)
                            if m:
                                ips = [s.strip() for s in m.group(1).split() if re.match(r'[\d.]+', s)]
                                if ips:
                                    return ips[:2]
                except OSError:
                    pass
        except OSError:
            pass

    # dhcpcd: domain_name_servers=A B C
    for path in glob.glob("/var/lib/dhcpcd/*.lease") + glob.glob("/var/lib/dhcpcd/dhcpcd-*.info"):
        try:
            with open(path) as f:
                for line in f:
                    m = re.match(r'domain_name_servers=(.*)', line)
                    if m:
                        ips = [s.strip() for s in m.group(1).split() if re.match(r'[\d.]+', s)]
                        if ips:
                            return ips[:2]
        except OSError:
            pass

    # NetworkManager via nmcli: look for dns_1 / dns_2 fields
    try:
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "DHCP4", "con", "show", "--active"],
            stderr=subprocess.DEVNULL, timeout=3, text=True,
        )
        dns_entries = re.findall(r'domain_name_servers\s*=\s*([\d.]+)', out)
        if not dns_entries:
            dns_entries = re.findall(r'dns[_\s]\d*\s*=\s*([\d.]+)', out)
        if dns_entries:
            return dns_entries[:2]
    except Exception:
        pass

    # Final fallback: resolv.conf
    # Try /run/systemd/resolve/resolv.conf first — on Debian/Ubuntu with systemd-resolved
    # this file contains the real upstream DNS IPs (not the 127.0.0.53 stub that
    # /etc/resolv.conf points to when systemd-resolved is active).
    # Fall back to /etc/resolv.conf for Alpine/udhcpc and other distros.
    for resolv_path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            ips: list[str] = []
            with open(resolv_path) as f:
                for line in f:
                    m = re.match(r'nameserver\s+([\d.]+)', line)
                    if not m:
                        continue
                    ip = m.group(1)
                    # Skip loopback and well-known public DNS servers
                    # (8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9 etc.) — they have no
                    # PTR records for private LAN addresses.
                    if ip.startswith('127.'):
                        continue
                    try:
                        addr = ipaddress.ip_address(ip)
                        if not addr.is_private:
                            continue
                    except ValueError:
                        continue
                    ips.append(ip)
            if ips:
                return ips[:2]
        except OSError:
            pass

    return []


def _get_network_service_ips() -> dict[str, list[str]]:
    """
    Returns {ip: [tag, ...]} identifying DNS1, DNS2, and DHCP servers.
    DNS servers are read from DHCP lease files (DHCP-provided nameservers).
    DHCP server IP is also read from lease files.
    """
    result: dict[str, list[str]] = {}

    # DNS servers from DHCP lease (what the router actually told us)
    dns_servers = _detect_dhcp_dns_servers()
    for idx, ip in enumerate(dns_servers, start=1):
        result.setdefault(ip, []).append(f"DNS{idx}")

    # DHCP server
    dhcp_ip = _detect_dhcp_server_ip()
    if dhcp_ip:
        result.setdefault(dhcp_ip, []).append("DHCP")

    return result


# ── Local MAC address reader ─────────────────────────────────────────────────

def _rdns_lookup(ip: str) -> Optional[str]:
    """
    Reverse-DNS lookup via the system resolver (/etc/resolv.conf).
    Works on any network where the local DNS server has PTR records
    (AdGuard Home, Pi-hole, dnsmasq, Windows DNS, ISP DNS, etc.).
    """
    try:
        name = socket.gethostbyaddr(ip)[0]
        # Reject results that are just the IP back, or clearly external PTR junk
        if name and name != ip and not name.endswith('.in-addr.arpa'):
            return name
    except (socket.herror, socket.gaierror, OSError):
        pass
    return None


def _get_iface_mac(iface: str) -> Optional[str]:
    """
    Read the hardware MAC address of a local network interface.
    Tries /sys/class/net/<iface>/address first, falls back to `ip link`.
    """
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip().upper()
            if mac and mac != "00:00:00:00:00:00":
                return mac
    except OSError:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "link", "show", iface], text=True, timeout=3
        )
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", out, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


# Cache for nmap MAC prefix DB {oui_upper_no_colons: vendor_string}
_oui_cache: dict[str, str] = {}
_oui_loaded: bool = False

def _lookup_vendor_from_mac(mac: str) -> Optional[str]:
    """
    Look up vendor name from MAC OUI using nmap's nmap-mac-prefixes database.
    Falls back gracefully if the file is absent.
    """
    global _oui_cache, _oui_loaded
    if not mac or len(mac) < 8:
        return None
    oui = mac.replace(":", "").replace("-", "")[:6].upper()
    if not _oui_loaded:
        _oui_loaded = True
        for path in (
            "/usr/share/nmap/nmap-mac-prefixes",
            "/usr/share/arp-scan/ieee-oui.txt",
        ):
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            _oui_cache[parts[0].upper()] = parts[1]
                if _oui_cache:
                    break
            except OSError:
                pass
    return _oui_cache.get(oui)


# Port → mDNS-style service type (used to synthesise service chips from open ports)
_PORT_SERVICE_MAP: dict[int, str] = {
    21:   "_ftp._tcp",
    22:   "_ssh._tcp",
    25:   "_smtp._tcp",
    80:   "_http._tcp",
    110:  "_pop3._tcp",
    143:  "_imap._tcp",
    443:  "_https._tcp",
    139:  "_smb._tcp",
    445:  "_smb._tcp",
    548:  "_afpovertcp._tcp",
    631:  "_ipp._tcp",
    1883: "_mqtt._tcp",
    1884: "_mqtt._tcp",
    3389: "_rdp._tcp",
    5900: "_vnc._tcp",
    6000: "_x11._tcp",
    8080: "_http._tcp",
    8443: "_https._tcp",
    9100: "_pdl-datastream._tcp",
}

def _infer_services_from_ports(device: "DeviceResult") -> None:
    """
    For devices with open ports but no service chips (mDNS/UPnP/WSD found nothing),
    synthesise mDNS-style service type strings from well-known port numbers so the
    frontend can display SSH / SMB / MQTT / etc. chips.
    """
    if not device.ports:
        return
    for p in device.ports:
        svc = _PORT_SERVICE_MAP.get(p.port)
        if svc and svc not in device.services:
            device.services.append(svc)



# ── Smart role inference ───────────────────────────────────────────────────────

def _refine_role(device: "DeviceResult") -> None:
    """
    Upgrade the generic 'Host' role to something meaningful using
    vendor, model, OS guess, and service strings gathered so far.
    Always called twice: after pre-scan enrichment AND after port-scan.
    GATEWAY/ROUTER and THIS HOST are never overwritten.
    """
    if device.role not in ("Host", "IOT DEVICE"):
        return

    vendor = (device.vendor or "").lower()
    model  = (device.model or "").lower()
    os_g   = (device.os_guess or "").lower()
    svcs   = " ".join(s.lower() for s in device.services)
    combo  = f"{vendor} {model} {os_g} {svcs}"
    # vendor+model only (no services) — used for brand-based rules prone to false positives
    id_combo = f"{vendor} {model}"

    # Ordered: first matching rule wins
    if any(k in combo for k in ["camera", "ipcam", "doorbell", "nvr", "dvr", "webcam",
                                   "hikvision", "dahua", "nest cam", "nest hello",
                                   "nest dropcam", "dropcam",
                                   "blink camera", "blink mini", "blink sync",
                                   "ring camera", "ring doorbell", "ring floodlight"]):
        device.role = "CAMERA/NVR"
    elif any(k in id_combo for k in ["nest", "nest labs", "blink", "ring"]):
        # Match brand names only in vendor/model — "ring" is a substring of "renderingcontrol"
        device.role = "CAMERA/NVR"
    elif any(k in combo for k in ["avtransport", "renderingcontrol", "wiim", "sonos",
                                   "chromecast", "eureka", "fire tv", "apple tv", "roku",
                                   "kodi", "volumio", "squeezebox", "linkplay"]):
        device.role = "MEDIA PLAYER"
    elif any(k in combo for k in ["contentdirectory", "minidlna", "plex", "emby",
                                   "jellyfin", "readymedia", "windows media connect"]):
        device.role = "MEDIA SERVER"
    elif any(k in combo for k in ["hue bridge", "philips hue", "smartthings", "vera",
                                   "hubitat", "home assistant", "homebridge"]):
        device.role = "SMART HUB"
    elif any(k in combo for k in ["tado", "ecobee", "thermostat", "nest thermostat"]):
        device.role = "SMART THERMOSTAT"
    elif any(k in combo for k in ["synology", "qnap", "asustor", "diskstation", "nas"]):
        device.role = "NAS"
    elif any(k in combo for k in ["printer", "printbasic", "printenhanced", "ipp", "cups"]):
        device.role = "PRINTER"
    elif any(k in combo for k in ["switch", "cisco slm", "cisco sg", "netgear gs",
                                   "ubiquiti", "unifi", "accesspoint", "access point",
                                   "wireless", "zyxel", "aruba", "ruckus"]):
        device.role = "NETWORK DEVICE"
    elif any(k in combo for k in ["amazon echo", "alexa", "google home", "smart speaker"]):
        device.role = "SMART SPEAKER"
    elif any(k in combo for k in ["espressif", "tuya", "tasmota", "iteadstudio",
                                   "shelly", "sonoff", "mqtt"]):
        device.role = "IOT DEVICE"




def _get_local_interfaces() -> list[dict]:
    """
    Returns list of dicts: {iface, ip, cidr, gateway}
    Uses `ip -o -4 addr show` and `ip route` — available on Alpine with iproute2.
    Falls back to /proc/net/fib_trie parsing if iproute2 missing.
    """
    interfaces = []
    try:
        addr_out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"], text=True, timeout=5
        )
        route_out = subprocess.check_output(
            ["ip", "-4", "route", "show"], text=True, timeout=5
        )
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log.error("ip command failed: %s", e)
        return interfaces

    # Parse default gateway per interface
    gateways: dict[str, str] = {}
    for line in route_out.splitlines():
        # default via 192.168.1.1 dev eth0
        m = re.match(r"default via (\S+) dev (\S+)", line)
        if m:
            gateways[m.group(2)] = m.group(1)

    # Parse addresses
    for line in addr_out.splitlines():
        # 2: eth0    inet 192.168.1.100/24 brd ...
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        iface, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        if ip.startswith("127."):
            continue
        # Skip virtual/container interfaces
        _VIRTUAL_PREFIXES = ("docker", "br-", "virbr", "veth", "lo", "tun", "tap", "dummy", "hassio", "haos")
        if any(iface.startswith(p) for p in _VIRTUAL_PREFIXES):
            log.debug("Skipping virtual interface: %s (%s)", iface, ip)
            continue
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        cidr = str(net)
        # Skip huge subnets (VPNs /0.../7) and host-only /32
        if prefix < 8 or prefix > 30:
            continue
        interfaces.append({
            "iface": iface,
            "ip": ip,
            "cidr": cidr,
            "gateway": gateways.get(iface, ""),
            "prefix": prefix,
        })

    # Deduplicate by CIDR
    seen: set[str] = set()
    unique = []
    for ifc in interfaces:
        if ifc["cidr"] not in seen:
            seen.add(ifc["cidr"])
            unique.append(ifc)
    return unique


def _get_ipv6_interfaces() -> list[dict]:
    """
    Returns list of dicts: {iface, ipv6, prefix, scope}
    scope: 'link-local' | 'ula' | 'global'
    Skips loopback, multicast, and virtual/container interfaces.
    """
    interfaces = []
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-6", "addr", "show"], text=True, timeout=5
        )
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log.debug("ip -6 addr show failed: %s", e)
        return interfaces

    _VIRTUAL_PREFIXES = ("docker", "br-", "virbr", "veth", "lo", "tun", "tap", "dummy", "hassio", "haos")
    for line in out.splitlines():
        # 2: eth0    inet6 fe80::1/64 scope link
        m = re.match(r"\d+:\s+(\S+)\s+inet6\s+([0-9a-f:]+)/(\d+)\s+scope\s+(\w+)", line)
        if not m:
            continue
        iface, ipv6, prefix_str, scope_kw = m.group(1), m.group(2), m.group(3), m.group(4)
        if any(iface.startswith(p) for p in _VIRTUAL_PREFIXES):
            continue
        try:
            addr = ipaddress.ip_address(ipv6)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_multicast:
            continue
        prefix = int(prefix_str)
        if addr.is_link_local:
            scope_name = "link-local"
        elif isinstance(addr, ipaddress.IPv6Address) and (
            ipv6.startswith("fc") or ipv6.startswith("fd")
        ):
            scope_name = "ula"
            # Skip huge ULA subnets (smaller than /120 is safe to scan with neigh)
            if prefix > 128 or prefix < 48:
                continue
        else:
            scope_name = "global"
            continue  # skip public GUA — out of scope for LAN scanner
        interfaces.append({
            "iface": iface,
            "ipv6": ipv6,
            "prefix": prefix,
            "scope": scope_name,
        })
    return interfaces


async def _discover_ipv6_via_ndp(
    ipv6_ifaces: list[dict],
    loop: asyncio.AbstractEventLoop,
) -> list["DeviceResult"]:
    """
    Discover IPv6 hosts via ICMPv6 Neighbor Discovery Protocol:
      1. Send ICMPv6 all-nodes multicast (ff02::1%iface) to trigger NDP responses.
      2. Read the kernel IPv6 neighbor cache (`ip -6 neigh show`).
    Returns DeviceResult objects for each discovered reachable neighbor.
    """
    devices: list["DeviceResult"] = []
    seen_ips: set[str] = set()

    async def _find_neighbors(ifc: dict) -> list["DeviceResult"]:
        iface = ifc["iface"]
        local_ipv6 = ifc["ipv6"]
        scope = ifc["scope"]
        result: list["DeviceResult"] = []

        # Trigger NDP by pinging all-nodes multicast
        for cmd in (
            ["ping6", "-c", "2", "-W", "1", "-I", iface, "ff02::1"],
            ["ping",  "-6", "-c", "2", "-W", "1", "-I", iface, f"ff02::1%{iface}"],
        ):
            try:
                await loop.run_in_executor(
                    None,
                    lambda c=cmd: subprocess.run(c, capture_output=True, timeout=5),
                )
                break
            except Exception:
                pass

        # Read neighbor cache
        try:
            neigh_out = await loop.run_in_executor(
                None,
                lambda: subprocess.check_output(
                    ["ip", "-6", "neigh", "show", "dev", iface],
                    text=True, timeout=5,
                ),
            )
        except Exception as e:
            log.debug("ip -6 neigh show failed for %s: %s", iface, e)
            return result

        # Determine subnet CIDR for this interface
        if scope == "link-local":
            subnet_cidr = "fe80::/64"
        else:
            try:
                net = ipaddress.ip_network(f"{local_ipv6}/{ifc['prefix']}", strict=False)
                subnet_cidr = str(net)
            except ValueError:
                subnet_cidr = f"{local_ipv6}/{ifc['prefix']}"

        # Parse each neighbor entry
        # Format: "fe80::1:2:3:4 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        _DEAD_STATES = {"FAILED", "INCOMPLETE", "NONE"}
        for line in neigh_out.splitlines():
            parts = line.split()
            if not parts:
                continue
            ipv6_addr = parts[0]
            # Skip self, multicast, loopback
            if ipv6_addr == local_ipv6:
                continue
            try:
                addr = ipaddress.ip_address(ipv6_addr)
                if addr.is_loopback or addr.is_multicast:
                    continue
            except ValueError:
                continue

            # Skip entries with dead states
            state = parts[-1].upper() if len(parts) > 1 else ""
            if state in _DEAD_STATES:
                continue

            # Extract MAC (lladdr field)
            mac: Optional[str] = None
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    candidate = parts[idx + 1].upper()
                    if candidate != "00:00:00:00:00:00":
                        mac = candidate

            # For link-local IPs, include interface scope so nmap can route them
            display_ip = f"{ipv6_addr}%{iface}" if addr.is_link_local else ipv6_addr

            if display_ip not in seen_ips:
                seen_ips.add(display_ip)
                vendor = _lookup_vendor_from_mac(mac) if mac else None
                result.append(DeviceResult(
                    ip=display_ip,
                    subnet=subnet_cidr,
                    iface=iface,
                    mac=mac,
                    vendor=vendor,
                    role="Host",
                ))
        return result

    batches = await asyncio.gather(*[_find_neighbors(ifc) for ifc in ipv6_ifaces])
    for batch in batches:
        devices.extend(batch)

    log.debug("IPv6 NDP: discovered %d neighbor(s)", len(devices))
    return devices



def _read_arp_table() -> dict[str, str]:
    """Read /proc/net/arp → {ip: mac_upper} for all known LAN hosts."""
    arp: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                # Fields: IP HW-type Flags MAC Mask Device
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    arp[parts[0]] = parts[3].upper()
    except OSError as e:
        log.debug("ARP table read failed: %s", e)
    return arp


# ── DHCP leases ───────────────────────────────────────────────────────────────

_DHCP_LEASE_PATHS = [
    "/var/lib/misc/dnsmasq.leases",   # dnsmasq default
    "/tmp/dhcp.leases",               # OpenWrt / DD-WRT
    "/var/lib/dhcp/dhclient.leases",  # ISC dhclient
    "/etc/pihole/dhcp.leases",        # Pi-hole
]


def _read_dhcp_leases() -> dict[str, str]:
    """Read DHCP lease files → {ip: hostname}. Handles dnsmasq line format."""
    import glob
    leases: dict[str, str] = {}
    for path in _DHCP_LEASE_PATHS:
        for resolved in glob.glob(path):
            try:
                with open(resolved) as f:
                    for line in f:
                        # dnsmasq format: <epoch> <mac> <ip> <hostname> <clientid>
                        parts = line.split()
                        if len(parts) >= 4 and parts[3] not in ("*", ""):
                            leases[parts[2]] = parts[3]
            except OSError:
                pass
    return leases


# ── mDNS / DNS-SD — pure Python (no avahi-daemon needed) ─────────────────────

def _query_mdns() -> tuple[dict[str, str], dict[str, list[str]], dict[str, str]]:
    """
    Pure-Python mDNS/DNS-SD service discovery using raw UDP multicast.
    Sends PTR queries to 224.0.0.251:5353 and parses responses (PTR/SRV/A/TXT).
    No avahi-daemon required — works directly with network_mode: host + NET_RAW.
    Returns:
      hostnames : {ip: hostname}
      services  : {ip: [service_type, ...]}   e.g. ["_airplay._tcp", "_raop._tcp"]
      models    : {ip: model_string}           from TXT records
    """
    MDNS_ADDR  = "224.0.0.251"
    MDNS_PORT  = 5353
    LISTEN_SECS = 6.0

    # Service types to actively query (covers home automation, media, IoT, infra)
    QTYPES = [
        "_services._dns-sd._udp.local",
        "_airplay._tcp.local",   "_raop._tcp.local",
        "_googlecast._tcp.local","_homekit._tcp.local", "_hap._tcp.local",
        "_http._tcp.local",      "_https._tcp.local",
        "_ssh._tcp.local",       "_sftp-ssh._tcp.local",
        "_smb._tcp.local",       "_printer._tcp.local",
        "_ipp._tcp.local",       "_pdl-datastream._tcp.local",
        "_afpovertcp._tcp.local","_nfs._tcp.local",
        "_rdp._tcp.local",       "_vnc._tcp.local",
        "_workstation._tcp.local","_daap._tcp.local",
        "_spotify-connect._tcp.local","_mqtt._tcp.local",
        "_esphomelib._tcp.local","_arduino._tcp.local",
        "_home-sharing._tcp.local",
    ]

    # ── DNS helpers ──────────────────────────────────────────────────────────
    def _enc(name: str) -> bytes:
        """Encode a DNS name (labels with length prefixes)."""
        out = b""
        for part in name.rstrip(".").split("."):
            e = part.encode()
            out += bytes([len(e)]) + e
        return out + b"\x00"

    def _parse_name(data: bytes, off: int, depth: int = 0) -> tuple[str, int]:
        """Parse a DNS compressed name, returns (name_str, new_offset)."""
        if depth > 10 or off >= len(data):
            return "", off
        parts: list[str] = []
        jumped_to = -1
        while off < len(data):
            length = data[off]
            if length == 0:
                off += 1
                break
            elif (length & 0xC0) == 0xC0:     # compression pointer
                if off + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[off + 1]
                if jumped_to == -1:
                    jumped_to = off + 2
                part, _ = _parse_name(data, ptr, depth + 1)
                parts.append(part)
                break
            else:
                off += 1
                parts.append(data[off:off + length].decode("utf-8", errors="ignore"))
                off += length
        return ".".join(parts), (jumped_to if jumped_to != -1 else off)

    def _parse_records(data: bytes) -> list[tuple[str, int, int, int]]:
        """
        Parse all resource records from a DNS/mDNS response.
        Returns [(name, rtype, rdata_offset_in_data, rdlen), ...].
        """
        records: list[tuple[str, int, int, int]] = []
        if len(data) < 12:
            return records
        try:
            _, flags, qdc, anc, nsc, arc = struct.unpack_from("!HHHHHH", data, 0)
        except struct.error:
            return records
        if not (flags & 0x8000):      # ignore queries, only process responses
            return records
        off = 12
        for _ in range(qdc):          # skip question section
            _, off = _parse_name(data, off)
            off += 4
            if off > len(data):
                return records
        for _ in range(anc + nsc + arc):
            if off >= len(data):
                break
            name, off = _parse_name(data, off)
            if off + 10 > len(data):
                break
            try:
                rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            except struct.error:
                break
            off += 10
            records.append((name, rtype, off, rdlen))
            off += rdlen
        return records

    # ── Discovery ─────────────────────────────────────────────────────────────
    hostnames: dict[str, str]        = {}
    services:  dict[str, list[str]]  = {}
    models:    dict[str, str]        = {}
    # intermediate maps
    ptr_map:   dict[str, list[str]]  = {}   # svc_type → [instance, ...]
    srv_map:   dict[str, tuple[str, int]] = {}  # instance → (target_host, port)
    a_map:     dict[str, str]        = {}   # hostname → ip
    txt_map:   dict[str, bytes]      = {}   # instance → raw TXT rdata

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.bind(("", MDNS_PORT))
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)

        def _send_queries() -> None:
            CHUNK = 8
            for i in range(0, len(QTYPES), CHUNK):
                chunk = QTYPES[i:i + CHUNK]
                hdr  = struct.pack("!HHHHHH", 0, 0, len(chunk), 0, 0, 0)
                body = b"".join(_enc(n) + struct.pack("!HH", 12, 0x8001) for n in chunk)
                try:
                    sock.sendto(hdr + body, (MDNS_ADDR, MDNS_PORT))
                except OSError:
                    pass
                time.sleep(0.05)

        _send_queries()                          # first burst
        query_2_at = time.monotonic() + 2.5      # second burst at t+2.5s
        second_sent = False

        deadline = time.monotonic() + LISTEN_SECS
        while time.monotonic() < deadline:
            if not second_sent and time.monotonic() >= query_2_at:
                _send_queries()
                second_sent = True

            rem = deadline - time.monotonic()
            r, _, _ = select.select([sock], [], [], min(rem, 0.3))
            if not r:
                continue
            try:
                pkt, _ = sock.recvfrom(4096)
            except OSError:
                continue

            for name, rtype, rd_off, rdlen in _parse_records(pkt):
                nl = name.lower().rstrip(".")
                if rtype == 1 and rdlen == 4:               # A record
                    a_map[nl] = socket.inet_ntoa(pkt[rd_off:rd_off + 4])
                elif rtype == 12:                            # PTR
                    inst, _ = _parse_name(pkt, rd_off)
                    inst = inst.rstrip(".")
                    if inst:
                        ptr_map.setdefault(nl, [])
                        if inst not in ptr_map[nl]:
                            ptr_map[nl].append(inst)
                elif rtype == 33 and rdlen >= 7:             # SRV
                    port = struct.unpack_from("!H", pkt, rd_off + 4)[0]
                    target, _ = _parse_name(pkt, rd_off + 6)
                    srv_map[nl] = (target.lower().rstrip("."), port)
                elif rtype == 16:                            # TXT
                    txt_map[nl] = pkt[rd_off:rd_off + rdlen]

    except OSError as e:
        log.debug("mDNS raw socket error: %s", e)
        return hostnames, services, models
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # ── Resolve instance→SRV→A→IP and populate output dicts ─────────────────
    for svc_type, instances in ptr_map.items():
        svc_short = svc_type.removesuffix(".local")
        for inst in instances:
            inst_l = inst.lower().rstrip(".")
            srv = srv_map.get(inst_l)
            if not srv:
                continue
            target, _port = srv
            ip = a_map.get(target)
            if not ip:
                continue

            if ip not in hostnames:
                hn = target.removesuffix(".local")
                if hn:
                    hostnames[ip] = hn

            services.setdefault(ip, [])
            if svc_short and svc_short not in services[ip]:
                services[ip].append(svc_short)

            if ip not in models:
                txt = txt_map.get(inst_l, b"")
                off = 0
                while off < len(txt):
                    slen = txt[off]; off += 1
                    if off + slen > len(txt):
                        break
                    kv = txt[off:off + slen].decode("utf-8", errors="ignore")
                    off += slen
                    kv_l = kv.lower()
                    for key in ("model=", "md=", "am="):
                        if kv_l.startswith(key):
                            val = kv[len(key):].strip()
                            if val:
                                models[ip] = val
                                break

    log.debug("mDNS: %d hostnames, %d IPs with services, %d models",
              len(hostnames), len(services), len(models))
    return hostnames, services, models


# ── UPnP / SSDP discovery ─────────────────────────────────────────────────────

def _query_upnp(timeout: float = 3.0) -> dict[str, dict]:
    """
    Send UPnP M-SEARCH multicast, collect responses, fetch device description XML.
    Returns {ip: {"name": ..., "model": ..., "manufacturer": ..., "services": [...]}}
    """
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    MSEARCH = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )
    results: dict[str, dict] = {}
    location_by_ip: dict[str, str] = {}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(MSEARCH.encode(), (SSDP_ADDR, SSDP_PORT))

        deadline = __import__("time").time() + timeout
        while __import__("time").time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                text = data.decode(errors="replace")
                # Extract LOCATION header
                loc_match = re.search(r"LOCATION:\s*(\S+)", text, re.IGNORECASE)
                if loc_match and ip not in location_by_ip:
                    location_by_ip[ip] = loc_match.group(1)
            except socket.timeout:
                break
    except OSError as e:
        log.debug("UPnP/SSDP socket error: %s", e)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Fetch description XML for each unique device
    import urllib.request
    for ip, location in location_by_ip.items():
        try:
            with urllib.request.urlopen(location, timeout=3) as resp:
                xml_data = resp.read(32768)
            root = ET.fromstring(xml_data)
            ns = {"u": "urn:schemas-upnp-org:device-1-0"}

            def _txt(tag: str) -> str:
                el = root.find(f".//u:{tag}", ns)
                return (el.text or "").strip() if el is not None else ""

            name = _txt("friendlyName") or _txt("modelName")
            model = _txt("modelName") or _txt("modelNumber")
            manufacturer = _txt("manufacturer")
            # Collect service types
            svc_types = [
                (el.text or "").strip()
                for el in root.findall(".//u:serviceType", ns)
                if el.text
            ]
            results[ip] = {
                "name": name,
                "model": model,
                "manufacturer": manufacturer,
                "services": svc_types,
            }
        except Exception as e:
            log.debug("UPnP description fetch failed for %s: %s", ip, e)

    return results


# ── WSD (Web Services on Devices) — Windows/printers ────────────────────────

def _query_wsd(timeout: float = 3.0) -> dict[str, str]:
    """
    Send WS-Discovery Probe multicast on UDP 3702.
    Returns {ip: friendly_name} for responding devices (typically Windows PCs, printers).
    """
    WSD_ADDR = "239.255.255.250"
    WSD_PORT = 3702
    PROBE = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<soap:Header>'
        '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
        '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
        '<wsa:MessageID>urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890</wsa:MessageID>'
        '</soap:Header>'
        '<soap:Body>'
        '<wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe>'
        '</soap:Body>'
        '</soap:Envelope>'
    )
    results: dict[str, str] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(PROBE.encode(), (WSD_ADDR, WSD_PORT))

        deadline = __import__("time").time() + timeout
        while __import__("time").time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
                ip = addr[0]
                text = data.decode(errors="replace")
                # Try to extract computer name from XAddrs or wsdp:Name
                name_match = re.search(r"<[^>]*Name[^>]*>([^<]{2,64})</", text)
                if name_match and ip not in results:
                    results[ip] = name_match.group(1).strip()
                elif ip not in results:
                    results[ip] = "WSD Device"
            except socket.timeout:
                break
    except OSError as e:
        log.debug("WSD socket error: %s", e)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return results


# ── SNMP enrichment ───────────────────────────────────────────────────────────

def _snmp_query(ip: str) -> dict[str, str]:
    """
    Query SNMP v2c community 'public' for sysName and sysDescr.
    Returns dict with keys 'name' and/or 'descr'. Empty on any failure.
    Timeout: 2s, 0 retries — best-effort only.
    """
    _OIDS = {
        "name":  "1.3.6.1.2.1.1.5.0",   # sysName
        "descr": "1.3.6.1.2.1.1.1.0",   # sysDescr
    }
    info: dict[str, str] = {}
    for key, oid in _OIDS.items():
        try:
            out = subprocess.check_output(
                ["snmpget", "-v2c", "-c", "public", "-t", "2", "-r", "0", ip, oid],
                text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
            # e.g.: SNMPv2-MIB::sysName.0 = STRING: myrouter
            m = re.search(r'=\s+\S+:\s+(.+)', out)
            if m:
                val = m.group(1).strip().strip('"')
                if val:
                    info[key] = val
        except FileNotFoundError:
            log.debug("snmpget not available, skipping SNMP enrichment")
            break  # no point trying further OIDs
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass  # host doesn't speak SNMP — normal
    return info


# IPs that didn't respond to SNMP — skip on future scans to avoid timeout penalty
_snmp_dead: set[str] = set()


def _snmp_walk_gateway_arp(gateway_ip: str) -> dict[str, str]:
    """
    Walk ipNetToMediaTable (1.3.6.1.2.1.4.22.1.2) on the gateway router via SNMPv2c.
    Returns {ip: MAC_UPPER} for all entries in the router's ARP cache — i.e. every
    device the router has seen recently, including those that don't respond to local ARP.
    Requires net-snmp-tools (snmpbulkwalk). Silent on any failure.
    Gateways that don't respond are cached in _snmp_dead to avoid repeated timeouts.
    """
    if not gateway_ip or gateway_ip in _snmp_dead:
        return {}
    community = config.SNMP_COMMUNITY
    result: dict[str, str] = {}
    try:
        out = subprocess.check_output(
            [
                "snmpbulkwalk", "-v2c", "-c", community,
                "-t", "3", "-r", "0",
                "-Oqn",   # quiet + numeric OIDs — no MIB needed
                gateway_ip,
                "1.3.6.1.2.1.4.22.1.2",  # ipNetToMediaPhysAddress
            ],
            text=True, timeout=6, stderr=subprocess.DEVNULL,
        )
        # Each line: .1.3.6.1.2.1.4.22.1.2.<ifIndex>.<a>.<b>.<c>.<d>  <mac>
        # MAC may be colon-hex (aa:bb:cc:dd:ee:ff) or space-separated hex bytes
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # Extract the trailing 4 octets of the OID as IP
            oid_match = re.search(r'\.(?:\d+)\.((\d+\.){3}\d+)\s', line)
            if not oid_match:
                continue
            ip = oid_match.group(1)  # e.g. "10.0.0.18"
            # Extract MAC — colon format
            mac_match = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line, re.IGNORECASE)
            if not mac_match:
                # Try space-separated hex bytes: "0 26 18 b4 30 d5"  → parse as 6 hex groups
                hex_match = re.search(r'(?:Hex-STRING:|STRING:)?\s*([0-9a-f]{1,2}(?:\s+[0-9a-f]{1,2}){5})\s*$', line, re.IGNORECASE)
                if hex_match:
                    parts = hex_match.group(1).split()
                    if len(parts) == 6:
                        mac_match_str = ":".join(p.zfill(2) for p in parts).upper()
                        result[ip] = mac_match_str
                continue
            result[ip] = mac_match.group(1).upper()
        if result:
            log.debug("SNMP gateway ARP: %d entries from %s", len(result), gateway_ip)
        else:
            # Empty response (SNMP up but no ARP table exposed) — don't blacklist
            log.debug("SNMP gateway ARP: empty response from %s", gateway_ip)
    except FileNotFoundError:
        log.debug("snmpbulkwalk not available — skipping gateway ARP walk")
        _snmp_dead.add(gateway_ip)  # tool missing — no point retrying ever
    except subprocess.TimeoutExpired:
        log.info("SNMP timeout on %s — will skip in future scans", gateway_ip)
        _snmp_dead.add(gateway_ip)
    except subprocess.SubprocessError as e:
        log.debug("SNMP walk error on %s: %s", gateway_ip, e)
        _snmp_dead.add(gateway_ip)
    return result


# ── nmap helpers ───────────────────────────────────────────────────────────────

def _run_nmap(args: list[str]) -> Optional[ET.Element]:
    """Run nmap with -oX - (XML stdout) and return parsed root element."""
    cmd = ["nmap", "-oX", "-"] + args
    log.debug("nmap cmd: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        if result.returncode not in (0, 1):
            log.warning("nmap stderr: %s", result.stderr[:500])
        return ET.fromstring(result.stdout)
    except subprocess.TimeoutExpired:
        log.error("nmap timed out: %s", " ".join(cmd))
        return None
    except ET.ParseError as e:
        log.error("nmap XML parse error: %s", e)
        return None


def _parse_ping_sweep(root: ET.Element, cidr: str, iface: str, gateway: str, local_ip: str) -> list[DeviceResult]:
    """Parse nmap ping sweep XML → list of DeviceResult (no ports yet)."""
    devices: list[DeviceResult] = []
    for host in root.findall(".//host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        mac_el = host.find("address[@addrtype='mac']")
        mac = mac_el.get("addr", "N/A").upper() if mac_el is not None else "N/A"
        vendor = mac_el.get("vendor") if mac_el is not None else None

        # RTT from ping timing
        rtt_ms: Optional[float] = None
        times_el = host.find("times")
        if times_el is not None:
            srtt = times_el.get("srtt")
            if srtt:
                rtt_ms = round(int(srtt) / 1000.0, 2)  # microseconds → ms

        # Hostname
        hostname = "N/A"
        hn_el = host.find(".//hostname[@type='PTR']")
        if hn_el is not None:
            hostname = hn_el.get("name", "N/A")

        # Role classification
        role = "Host"
        if ip == gateway:
            role = "GATEWAY/ROUTER"
        elif ip == local_ip:
            role = "THIS HOST"

        devices.append(DeviceResult(
            ip=ip,
            subnet=cidr,
            iface=iface,
            mac=mac if mac != "N/A" else None,
            hostname=hostname if hostname != "N/A" else None,
            rtt_ms=rtt_ms,
            role=role,
            vendor=vendor,
        ))
    return devices


def _parse_port_scan(root: ET.Element, device: DeviceResult) -> None:
    """Parse nmap port/service scan XML and update device in-place.

    Handles scripts: nbstat, http-title, smb-os-discovery, smb-enum-shares,
    upnp-info, dns-service-discovery, banner, ssl-cert.
    Supports both IPv4 and IPv6 targets (link-local scope stripped for matching).
    """
    ports: list[PortInfo] = []
    os_guess: Optional[str] = None

    # Strip link-local scope (fe80::1%eth0 → fe80::1) for nmap XML matching
    match_ip = device.ip.split("%")[0] if ":" in device.ip else device.ip

    for host in root.findall(".//host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None or addr_el.get("addr") != match_ip:
            continue

        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            svc_version = (
                f"{svc_el.get('product','')} {svc_el.get('version','')}".strip()
                if svc_el is not None else ""
            )
            # Use raw banner as version fallback when service detection found nothing
            if not svc_version:
                banner_el = port_el.find("script[@id='banner']")
                if banner_el is not None:
                    raw = banner_el.get("output", "").strip().splitlines()[0][:80]
                    if raw:
                        svc_version = f"[banner] {raw}"
            ports.append(PortInfo(
                port=int(port_el.get("portid", 0)),
                proto=port_el.get("protocol", "tcp"),
                state="open",
                service=svc_el.get("name", "") if svc_el is not None else "",
                version=svc_version,
            ))

        # OS detection (best guess)
        for osmatch in host.findall(".//osmatch"):
            name = osmatch.get("name", "")
            accuracy = int(osmatch.get("accuracy", "0"))
            if accuracy >= 70:
                os_guess = f"{name} ({accuracy}%)"
                break

        # ── Script result enrichment ───────────────────────────────────────────

        # PTR hostname (highest priority)
        if device.hostname is None:
            hn_el = host.find(".//hostname[@type='PTR']")
            if hn_el is not None:
                device.hostname = hn_el.get("name")

        # NetBIOS name
        if device.hostname is None:
            for script_el in host.findall(".//script[@id='nbstat']"):
                output = script_el.get("output", "")
                m = re.search(r"NetBIOS name:\s*([^,\s]+)", output, re.IGNORECASE)
                if m and m.group(1) not in ("<unknown>", ""):
                    device.hostname = m.group(1)
                    break

        # HTTP title (fallback hostname / label)
        if device.hostname is None:
            for script_el in host.findall(".//script[@id='http-title']"):
                title = script_el.get("output", "").strip()
                tl = title.lower()
                _useless = (
                    "site doesn't have a title",
                    "document moved", "object moved",
                    "301 ", "302 ", "303 ", "307 ", "308 ",
                    "400 ", "401 ", "403 ", "404 ", "500 ",
                    "access denied", "not found", "forbidden",
                    "redirect", "loading", "please wait",
                )
                if title and not any(tl.startswith(u) for u in _useless):
                    device.hostname = f"[{title[:40]}]"
                    break

        # SSL cert — extract CN/SAN as hostname if still missing
        if device.hostname is None:
            for script_el in host.findall(".//script[@id='ssl-cert']"):
                output = script_el.get("output", "")
                m = re.search(r"commonName=([^\s,/]+)", output)
                if m:
                    cn = m.group(1).strip()
                    if cn and "*" not in cn:
                        device.hostname = cn
                        break

        # SMB OS discovery — enriches OS guess
        if os_guess is None:
            for script_el in host.findall(".//script[@id='smb-os-discovery']"):
                output = script_el.get("output", "")
                m = re.search(r"OS:\s*([^\n]+)", output)
                if m:
                    os_guess = m.group(1).strip()[:120]
                    break

        # SMB shares → add as service entries
        for script_el in host.findall(".//script[@id='smb-enum-shares']"):
            output = script_el.get("output", "")
            shares = re.findall(r"\\\\[^\\]+\\(\S+)", output)
            for share in shares:
                entry = f"smb:{share}"
                if entry not in device.services:
                    device.services.append(entry)
            if shares:
                svc_entry = "SMB shares"
                if svc_entry not in device.services:
                    device.services.append(svc_entry)

        # UPnP info — extract device type and model/manufacturer
        for script_el in host.findall(".//script[@id='upnp-info']"):
            output = script_el.get("output", "")
            # Extract device type (e.g. "MediaRenderer", "InternetGatewayDevice")
            dt_match = re.search(r"deviceType[^:]*:\s*([^\n]+)", output, re.IGNORECASE)
            if dt_match:
                raw_dt = dt_match.group(1).strip()
                # Shorten full URN: urn:schemas-upnp-org:device:InternetGatewayDevice:1 → InternetGatewayDevice
                urn_seg = re.search(r":(?:device|service):([^:]+)", raw_dt, re.IGNORECASE)
                short_dt = urn_seg.group(1) if urn_seg else raw_dt[:60]
                entry = f"upnp:{short_dt}"
                if entry not in device.services:
                    device.services.append(entry)
            # Model/manufacturer
            if device.model is None:
                m = re.search(r"modelName[^:]*:\s*([^\n]+)", output, re.IGNORECASE)
                if m:
                    device.model = m.group(1).strip()[:80]
            if device.model is None:
                m = re.search(r"manufacturer[^:]*:\s*([^\n]+)", output, re.IGNORECASE)
                if m:
                    device.model = m.group(1).strip()[:80]

        # DNS service discovery — collect service types
        for script_el in host.findall(".//script[@id='dns-service-discovery']"):
            output = script_el.get("output", "")
            # Lines contain service type after last ';' or in parentheses
            for svc_type in re.findall(r"(_[a-zA-Z0-9\-]+\._(?:tcp|udp))", output):
                if svc_type not in device.services:
                    device.services.append(svc_type)

        break  # found our host

    device.ports = ports
    device.os_guess = os_guess


# ── Main scan entry point ──────────────────────────────────────────────────────

async def _scan_host(
    device: DeviceResult,
    index: int,
    total: int,
    semaphore: asyncio.Semaphore,
    loop: asyncio.AbstractEventLoop,
    timeout_s: float,
) -> None:
    """
    Two-phase nmap scan for a single host, emitting SSE events.

    Phase A — fast SYN sweep (all TCP) + UDP top-ports in parallel:
      nmap -sS -p- --open -T4 <ip>          (TCP)
      nmap -sU --top-ports 20 --open -T4 <ip>  (UDP, concurrent)

    Phase B — full service/OS/script scan only on discovered open ports:
      nmap -sV -p<csv> -O --script ... -T4 <ip>
    """
    async with semaphore:
        await sse_emit({
            "type": "port_scan_start",
            "ip": device.ip,
            "index": index,
            "total": total,
        })

        # Phase A: fast TCP port discovery — full SYN sweep across all 65535 ports.
        # UDP ports (mDNS/5353, SNMP/161, UPnP/1900 etc.) are already collected by
        # the pre-discovery phase (mDNS, SNMP, UPnP probes) — no parallel UDP scan needed.
        is_this_host = device.role == "THIS HOST"
        is_ipv6 = ":" in device.ip
        ipv6_flag = ["-6"] if is_ipv6 else []

        phase_a_args = ipv6_flag + [
            "-sT" if (is_this_host or is_ipv6) else "-sS",
            "-Pn",
            # For IPv6 link-local, -p- (65535 ports) is very slow and often hangs.
            # Use a targeted common-port list instead; vastly faster on fe80:: addresses.
            "-p21,22,23,25,53,80,110,139,143,443,445,554,587,631,993,995,"
            "1883,1900,3000,3001,3306,4000,5000,5357,7443,8008,8080,8081,"
            "8088,8090,8443,8888,9000,9090,9443,10000,20041,49152"
            if is_ipv6 else "-p-",
            "--open",
            "-T4",
            device.ip,
        ]

        phase_a_root = await loop.run_in_executor(None, _run_nmap, phase_a_args)

        open_ports: list[str] = []
        if phase_a_root is not None:
            match_ip = device.ip.split("%")[0] if is_ipv6 else device.ip
            for host in phase_a_root.findall(".//host"):
                addr_el = host.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    addr_el = host.find("address[@addrtype='ipv6']")
                if addr_el is None or addr_el.get("addr") != match_ip:
                    continue
                for port_el in host.findall(".//port"):
                    state_el = port_el.find("state")
                    if state_el is not None and state_el.get("state") == "open":
                        key = f"{port_el.get('portid')}/{port_el.get('protocol', 'tcp')}"
                        if key not in open_ports:
                            open_ports.append(key)

        # Signal Phase A complete — frontend advances progress bar to ~50 %
        await sse_emit({
            "type": "port_scan_progress",
            "ip": device.ip,
            "pct": 50,
        })

        if open_ports:
            # Phase B: detailed version/script scan on the exact open ports found by Phase A
            port_spec = ",".join(p.split("/")[0] for p in open_ports)
            phase_b_args = ipv6_flag + [
                "-sT" if (is_this_host or is_ipv6) else "-sV",
                "-Pn",
                f"-p{port_spec}",
                "-O",
                "-R",
                "-T4",
                "--script",
                "nbstat,http-title,http-server-header,smb-os-discovery,smb-enum-shares,"
                "smb-security-mode,upnp-info,dns-service-discovery,banner,ssl-cert,"
                "ssh-hostkey,snmp-sysdescr,snmp-interfaces",
                device.ip,
            ]
            if is_this_host or is_ipv6:
                phase_b_args.insert(len(ipv6_flag) + 1, "-sV")
            phase_b_root = await loop.run_in_executor(None, _run_nmap, phase_b_args)
            if phase_b_root is not None:
                _parse_port_scan(phase_b_root, device)
        elif is_this_host:
            # THIS HOST with no open ports found — still run -sV scan to get hostname/OS
            phase_b_args = [
                "-sT", "-sV", "-Pn",
                "-p22,53,80,443,8080,7979,8443,3000,5000,9000,9090",
                "-O", "-R",
                "-T4",
                device.ip,
            ]
            phase_b_root = await loop.run_in_executor(None, _run_nmap, phase_b_args)
            if phase_b_root is not None:
                _parse_port_scan(phase_b_root, device)
        else:
            # No open ports found by Phase A — probe a comprehensive set of common ports
            # with TCP connect scan so switches, NAS, cameras, IoT etc. get identified.
            # Covers: SSH, DNS, HTTP/S, SMB, NetBIOS, WSD, common mgmt ports.
            phase_b_args = ipv6_flag + [
                "-sT", "-sV", "-Pn",
                "-p21,22,23,25,53,80,110,139,143,443,445,"
                "554,587,631,993,995,1883,1900,3000,3001,3306,"
                "4000,5000,5357,7443,8080,8081,8088,8090,8443,"
                "8888,9000,9090,9443,10000,20041,49152",
                "--open",
                "-T4",
                "--script", "http-title,banner,ssl-cert,nbstat",
                device.ip,
            ]
            phase_b_root = await loop.run_in_executor(None, _run_nmap, phase_b_args)
            if phase_b_root is not None:
                _parse_port_scan(phase_b_root, device)

        # SNMP enrichment (parallel while phase B runs is not easily composable here,
        # but SNMP is fast — run after phase B)
        snmp_info = await loop.run_in_executor(None, _snmp_query, device.ip)
        if snmp_info.get("name") and device.hostname is None:
            device.hostname = snmp_info["name"]
        if snmp_info.get("descr") and device.os_guess is None:
            device.os_guess = snmp_info["descr"][:120]

        # Re-apply role inference with data from port scan (model/services may have been updated)
        # Also synthesise service chips from open ports for devices mDNS/UPnP didn't cover.
        _infer_services_from_ports(device)
        _refine_role(device)

        await sse_emit({
            "type": "host_done",
            "ip": device.ip,
            "mac": device.mac,
            "hostname": device.hostname,
            "rtt_ms": device.rtt_ms,
            "role": device.role,
            "ports": [
                {"port": p.port, "proto": p.proto, "service": p.service, "version": p.version}
                for p in device.ports
            ],
            "os_guess": device.os_guess,
            "vendor": device.vendor,
            "model": device.model,
            "services": device.services,
            "tags": device.tags,
            "subnet": device.subnet,
            "iface": device.iface,
        })


async def run_scan() -> list[DeviceResult]:
    """
    Full scan flow:
      1. Discover local interfaces (subnets, gateways).
      2. In parallel: ARP table, DHCP leases, mDNS/Bonjour, UPnP/SSDP, WSD.
      3. For each subnet: nmap ping sweep.
      4. Emit host_ping_done immediately (early UI display).
      5. Run two-phase parallel port scan (semaphore-limited concurrency).
      6. Enrich results with pre-collected discovery data.
    Emits SSE progress events via _sse_queue.
    """
    global _partial_devices, _partial_ping, _scanning_ips
    _partial_devices = []
    _partial_ping = {}
    _scanning_ips = set()
    all_devices: list[DeviceResult] = []

    await sse_emit({"type": "log", "level": "info", "msg": "Discovering local interfaces..."})
    interfaces = _get_local_interfaces()

    if not interfaces:
        await sse_emit({"type": "error", "msg": "No active network interfaces found."})
        return []

    await sse_emit({
        "type": "log", "level": "info",
        "msg": f"Found {len(interfaces)} interface(s): {', '.join(i['cidr'] for i in interfaces)}"
    })

    # Discover IPv6-capable interfaces (link-local + ULA)
    ipv6_ifaces = _get_ipv6_interfaces()
    if ipv6_ifaces:
        await sse_emit({
            "type": "log", "level": "info",
            "msg": f"IPv6: found {len(ipv6_ifaces)} interface(s) with link-local/ULA addresses",
        })

    loop = asyncio.get_running_loop()

    # ── Phase 0: parallel pre-discovery ────────────────────────────────────────
    await sse_emit({"type": "log", "level": "info",
                    "msg": "Running parallel pre-discovery (ARP, DHCP, mDNS, UPnP, WSD, SNMP)..."})

    # Collect gateways from all interfaces for SNMP ARP walk
    gateways = list({ifc["gateway"] for ifc in interfaces if ifc.get("gateway")})

    arp_table, dhcp_leases, mdns_result, upnp_info, wsd_names, net_roles = await asyncio.gather(
        loop.run_in_executor(None, _read_arp_table),
        loop.run_in_executor(None, _read_dhcp_leases),
        loop.run_in_executor(None, _query_mdns),
        loop.run_in_executor(None, _query_upnp),
        loop.run_in_executor(None, _query_wsd),
        loop.run_in_executor(None, _get_network_service_ips),
    )

    # IPv6 neighbor discovery (runs in parallel with the SNMP ARP walk below)
    async def _empty_ipv6() -> list[DeviceResult]:
        return []

    ipv6_task = asyncio.ensure_future(
        _discover_ipv6_via_ndp(ipv6_ifaces, loop) if ipv6_ifaces else _empty_ipv6()
    )

    # SNMP ARP walk on each gateway (runs after we know the gateways)
    gateway_arp: dict[str, str] = {}
    for gw in gateways:
        gateway_arp.update(await loop.run_in_executor(None, _snmp_walk_gateway_arp, gw))
    # Merge gateway ARP into our local ARP table (local ARP wins if already present)
    for ip, mac in gateway_arp.items():
        if ip not in arp_table:
            arp_table[ip] = mac

    # Await IPv6 NDP discovery (started concurrently during SNMP walk)
    ipv6_devices: list[DeviceResult] = await ipv6_task

    # _query_mdns now returns (hostnames, services, models)
    mdns_hostnames, mdns_services, mdns_models = mdns_result

    dns_tags = {ip: tags for ip, tags in net_roles.items() if any(t.startswith('DNS') for t in tags)}
    disc_counts = (
        f"ARP:{len(arp_table)}(+SNMP:{len(gateway_arp)})  DHCP:{len(dhcp_leases)}  "
        f"mDNS:{len(mdns_hostnames)}  UPnP:{len(upnp_info)}  WSD:{len(wsd_names)}  "
        f"DNS:{','.join(f'{ip}={tags}' for ip,tags in dns_tags.items()) or 'none'}"
    )
    await sse_emit({"type": "log", "level": "info", "msg": f"Pre-discovery done — {disc_counts}"})

    # Build the DNS server list for nmap reverse-PTR lookups.
    # - LAN DNS (AdGuard, Pi-hole, dnsmasq, Windows DNS) — filtered to private IPs only
    # - Gateway/router — always included: it often has PTR records for its own DHCP leases
    # Public DNS servers (8.8.8.8 etc.) are excluded — they have no PTR for LAN IPs.
    lan_dns_ips = [
        ip for ip, tags in net_roles.items()
        if any(t.startswith('DNS') for t in tags)
    ]

    timeout_s = config.SCAN_TIMEOUT_MS / 1000.0
    semaphore = asyncio.Semaphore(PORT_SCAN_CONCURRENCY)

    for ifc in interfaces:
        cidr = ifc["cidr"]
        iface = ifc["iface"]
        gateway = ifc["gateway"]
        local_ip = ifc["ip"]

        await sse_emit({"type": "subnet_start", "subnet": cidr, "iface": iface})
        await sse_emit({"type": "log", "level": "info", "msg": f"[{iface}] Ping sweep on {cidr}..."})

        # ── Phase 1: nmap ping sweep ───────────────────────────────────────────
        # -sn                  host discovery only (no port scan)
        # -PE                  ICMP echo request
        # -PS<ports>           TCP SYN probe — finds hosts that block ICMP but answer TCP
        # -PA<ports>           TCP ACK probe — finds stateful-firewall hosts
        # -T4 / --min-rate     faster sweep
        ping_args = [
            "-sn",
            "-PE",              # ICMP echo
            "-PS80,443,22,8080,8443,8008,9000,554,1883",  # TCP SYN probes
            "-PA80,443",        # TCP ACK probes (firewall bypass)
            "--min-rate", "300",
            "-T4",
            "-R",
        ]
        # Build --dns-servers: LAN DNS + gateway (router often has PTR from DHCP).
        # Deduplicate while preserving order; skip empty values.
        dns_candidates = lan_dns_ips + ([gateway] if gateway else [])
        seen: set[str] = set()
        nmap_dns_list = [x for x in dns_candidates if x and not (x in seen or seen.add(x))]
        if nmap_dns_list:
            ping_args += ["--dns-servers", ",".join(nmap_dns_list)]
        ping_args.append(cidr)
        if config.NMAP_EXTRA_ARGS:
            ping_args += config.NMAP_EXTRA_ARGS.split()

        ping_root = await loop.run_in_executor(None, _run_nmap, ping_args)
        if ping_root is None:
            await sse_emit({"type": "log", "level": "warn",
                            "msg": f"[{iface}] Ping sweep failed for {cidr}"})
            continue

        devices = _parse_ping_sweep(ping_root, cidr, iface, gateway, local_ip)

        # ── Enrich from pre-discovery ──────────────────────────────────────────
        for device in devices:
            ip = device.ip

            # MAC from ARP if not found by nmap
            if device.mac is None:
                device.mac = arp_table.get(ip)

            # THIS HOST: nmap never gets its own MAC via ARP — read from iface directly
            if device.mac is None and device.role == "THIS HOST":
                device.mac = _get_iface_mac(iface)

            # Vendor from OUI if nmap didn't provide it (e.g. THIS HOST has no ARP in nmap XML)
            if device.vendor is None and device.mac and device.mac != "N/A":
                device.vendor = _lookup_vendor_from_mac(device.mac)

            # Hostname priority: mDNS > DHCP > WSD name (WSD usually has computer names)
            if device.hostname is None:
                device.hostname = (
                    mdns_hostnames.get(ip)
                    or dhcp_leases.get(ip)
                    or wsd_names.get(ip)
                )

            # Network role tags (DNS1/DNS2/DHCP)
            device.tags = net_roles.get(ip, [])

            # mDNS services and model
            if mdns_services.get(ip):
                for svc in mdns_services[ip]:
                    if svc not in device.services:
                        device.services.append(svc)
            if device.model is None:
                device.model = mdns_models.get(ip)

            # UPnP enrichment
            upnp = upnp_info.get(ip, {})
            if upnp:
                if device.hostname is None and upnp.get("name"):
                    # Strip email addresses from UPnP friendlyName (e.g. Windows Media Player)
                    name = re.sub(r'\s*\S+@\S+\s*:?\s*', '', upnp["name"]).strip().strip(':').strip()
                    if name:
                        device.hostname = name
                if device.model is None:
                    device.model = upnp.get("model") or upnp.get("manufacturer")
                for svc in upnp.get("services", []):
                    if svc and svc not in device.services:
                        device.services.append(svc)

        # ── Parallel reverse-DNS fallback ──────────────────────────────────────
        # For devices still without a hostname after mDNS/DHCP/WSD/UPnP enrichment,
        # query the system DNS resolver in parallel. Works on any network where the
        # DNS server has PTR records (AdGuard, Pi-hole, dnsmasq, Windows DNS, etc.).
        no_name = [d for d in devices if d.hostname is None]
        if no_name:
            rdns_names = await asyncio.gather(
                *[loop.run_in_executor(None, _rdns_lookup, d.ip) for d in no_name]
            )
            for d, name in zip(no_name, rdns_names):
                if name:
                    d.hostname = name

        # Refine generic 'Host' role using vendor/model/services gathered so far
        for d in devices:
            _refine_role(d)

        await sse_emit({
            "type": "subnet_ping_done",
            "subnet": cidr,
            "count": len(devices),
            "msg": f"[{iface}] {cidr} → {len(devices)} hosts up",
        })
        await sse_emit({"type": "log", "level": "ok",
                        "msg": f"[{iface}] {len(devices)} hosts responding"})

        # ── Emit early display (before port scan) ─────────────────────────────
        for device in devices:
            await sse_emit({
                "type": "host_ping_done",
                "ip": device.ip,
                "mac": device.mac,
                "hostname": device.hostname,
                "rtt_ms": device.rtt_ms,
                "role": device.role,
                "vendor": device.vendor,
                "model": device.model,
                "services": device.services,
                "tags": device.tags,
                "subnet": device.subnet,
                "iface": device.iface,
            })

        # ── Phase 2: parallel two-phase port scan ─────────────────────────────
        await sse_emit({"type": "log", "level": "info",
                        "msg": f"[{iface}] Starting parallel port scan "
                               f"({min(PORT_SCAN_CONCURRENCY, len(devices))} concurrent)..."})

        scan_tasks = [
            _scan_host(device, i + 1, len(devices), semaphore, loop, timeout_s)
            for i, device in enumerate(devices)
        ]
        await asyncio.gather(*scan_tasks)

        all_devices.extend(devices)

    # Build MAC→IPv4 device index for IPv6 inheritance
    ipv4_by_mac: dict[str, "DeviceResult"] = {
        d.mac: d for d in all_devices if d.mac
    }

    # ── IPv6: emit and port-scan discovered neighbors ─────────────────────────
    if ipv6_devices:
        # Enrich with mDNS/DHCP hostnames where possible (IPv6 addresses may differ)
        for device in ipv6_devices:
            bare_ip = device.ip.split("%")[0]
            if device.hostname is None:
                device.hostname = (
                    mdns_hostnames.get(bare_ip)
                    or dhcp_leases.get(bare_ip)
                )
            if device.mac and device.vendor is None:
                device.vendor = _lookup_vendor_from_mac(device.mac)

            # ── Inherit role / hostname / model / ports / services from matching IPv4 device ──
            if device.mac and device.mac in ipv4_by_mac:
                v4 = ipv4_by_mac[device.mac]
                if not device.hostname and v4.hostname:
                    device.hostname = v4.hostname
                if not device.model and v4.model:
                    device.model = v4.model
                # Always inherit role from IPv4 (IPv4 scan has richer info)
                if v4.role not in ("Host", "IOT DEVICE"):
                    device.role = v4.role
                else:
                    _refine_role(device)
                # Inherit ports and services — IPv6 port scan is skipped for same-MAC
                # devices, so copy the authoritative data from the IPv4 entry.
                if not device.ports and v4.ports:
                    device.ports = v4.ports
                if not device.services and v4.services:
                    device.services = list(v4.services)
                if not device.os_guess and v4.os_guess:
                    device.os_guess = v4.os_guess
            else:
                _refine_role(device)

        await sse_emit({
            "type": "log", "level": "info",
            "msg": f"IPv6 NDP: {len(ipv6_devices)} neighbor(s) found — starting port scan...",
        })
        for device in ipv6_devices:
            await sse_emit({
                "type": "host_ping_done",
                "ip": device.ip,
                "mac": device.mac,
                "hostname": device.hostname,
                "rtt_ms": device.rtt_ms,
                "role": device.role,
                "vendor": device.vendor,
                "model": device.model,
                "services": device.services,
                "tags": device.tags,
                "subnet": device.subnet,
                "iface": device.iface,
            })

        # Only port-scan IPv6 devices that have NO matching IPv4 entry.
        # Devices with the same MAC were already fully scanned in the IPv4 pass —
        # running a second full -p- scan on their fe80:: address wastes time and
        # often hangs (link-local nmap scans are unreliable and can hit the 300s timeout).
        ipv6_scan_targets = [d for d in ipv6_devices if not (d.mac and d.mac in ipv4_by_mac)]
        ipv6_skip_count = len(ipv6_devices) - len(ipv6_scan_targets)
        if ipv6_skip_count:
            await sse_emit({
                "type": "log", "level": "info",
                "msg": f"IPv6: skipping port scan for {ipv6_skip_count} device(s) already scanned via IPv4 (same MAC).",
            })

        ipv6_tasks = [
            _scan_host(device, i + 1, len(ipv6_scan_targets), semaphore, loop, timeout_s)
            for i, device in enumerate(ipv6_scan_targets)
        ]
        await asyncio.gather(*ipv6_tasks)
        all_devices.extend(ipv6_devices)

    # NOTE: the SSE 'done' event is intentionally NOT emitted here.
    # It is emitted by _scan_job() in scheduler.py AFTER _save_scan() commits,
    # so the frontend only gets 'done' once the data is actually in the DB.
    # This prevents loadLastScan() from racing against a pending DB write.
    return all_devices, len(interfaces)
