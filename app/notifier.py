"""
notifier.py — Email notifications via Apprise (SMTP).

Sends alerts for:
  - New device discovered (MAC never seen before)
  - Device disappeared (was seen in last scan, absent in current)
  - Port change detected (a device opened or closed ports vs previous scan)
  - Scan error
"""

import logging
from typing import Optional

import apprise

from config import config

log = logging.getLogger("notifier")


def _build_apprise() -> Optional[apprise.Apprise]:
    """Build Apprise instance with SMTP target. Returns None if not configured."""
    if not config.NOTIFY_ENABLED:
        return None
    if not all([config.SMTP_HOST, config.SMTP_USER, config.SMTP_PASS, config.NOTIFY_TO]):
        log.warning("Notifications enabled but SMTP config incomplete — skipping.")
        return None

    ap = apprise.Apprise()
    # Apprise SMTP URL format:
    # mailto://user:pass@host:port/to_address?from=from_address&name=NetSonar
    url = (
        f"mailto://{config.SMTP_USER}:{config.SMTP_PASS}"
        f"@{config.SMTP_HOST}:{config.SMTP_PORT}"
        f"/{config.NOTIFY_TO}"
        f"?from={config.NOTIFY_FROM or config.SMTP_USER}"
        f"&name=NetSonar"
        f"&mode=starttls"
    )
    ap.add(url)
    return ap


async def notify_new_device(mac: str, ip: str, hostname: Optional[str], alias: Optional[str]) -> None:
    ap = _build_apprise()
    if ap is None:
        return
    label = alias or hostname or ip
    title = f"[NetSonar] New device detected: {label}"
    body = (
        f"A new device has appeared on your network.\n\n"
        f"  IP:       {ip}\n"
        f"  MAC:      {mac}\n"
        f"  Hostname: {hostname or 'N/A'}\n\n"
        f"If this device is unknown, investigate immediately."
    )
    await ap.async_notify(title=title, body=body)
    log.info("Notified: new device %s (%s)", mac, ip)


async def notify_device_gone(mac: str, last_ip: str, alias: Optional[str]) -> None:
    ap = _build_apprise()
    if ap is None:
        return
    label = alias or last_ip
    title = f"[NetSonar] Device offline: {label}"
    body = (
        f"A previously seen device is no longer responding.\n\n"
        f"  MAC:      {mac}\n"
        f"  Last IP:  {last_ip}\n"
        f"  Alias:    {alias or 'N/A'}\n"
    )
    await ap.async_notify(title=title, body=body)
    log.info("Notified: device gone %s (was %s)", mac, last_ip)


async def notify_scan_summary(host_count: int, new_count: int, gone_count: int, subnets: list[str], port_change_count: int = 0) -> None:
    """Send a summary email after each scan (only when there are notable events)."""
    if new_count == 0 and gone_count == 0 and port_change_count == 0:
        return  # nothing interesting to report
    ap = _build_apprise()
    if ap is None:
        return
    title = f"[NetSonar] Scan complete — {new_count} new, {gone_count} gone, {port_change_count} port changes"
    body = (
        f"NetSonar scan completed.\n\n"
        f"  Subnets scanned:  {', '.join(subnets)}\n"
        f"  Total hosts:      {host_count}\n"
        f"  New devices:      {new_count}\n"
        f"  Devices gone:     {gone_count}\n"
        f"  Port changes:     {port_change_count}\n"
    )
    await ap.async_notify(title=title, body=body)


async def notify_scan_error(error: str) -> None:
    ap = _build_apprise()
    if ap is None:
        return
    await ap.async_notify(
        title="[NetSonar] Scan error",
        body=f"A scheduled scan failed with error:\n\n{error}"
    )


async def notify_ports_changed(
    mac: str,
    ip: str,
    alias: Optional[str],
    opened: list[dict],
    closed: list[dict],
) -> None:
    """
    Alert when a known device opens or closes ports between scans.
    Both *opened* and *closed* are lists of port-info dicts
    (keys: port, proto, service, version).
    """
    ap = _build_apprise()
    if ap is None:
        return
    label = alias or ip

    def _fmt(ports: list[dict]) -> str:
        if not ports:
            return "  —"
        return "\n".join(
            f"  {p['port']}/{p.get('proto','tcp')}  {p.get('service','?')}"
            + (f"  [{p['version']}]" if p.get("version") else "")
            for p in sorted(ports, key=lambda x: x["port"])
        )

    title = f"[NetSonar] Port change on {label}"
    body = (
        f"Open ports changed on device: {label}\n\n"
        f"  MAC: {mac}\n"
        f"  IP:  {ip}\n\n"
        f"NEWLY OPENED ({len(opened)}):\n{_fmt(opened)}\n\n"
        f"NEWLY CLOSED ({len(closed)}):\n{_fmt(closed)}\n\n"
        f"If unexpected, investigate immediately."
    )
    await ap.async_notify(title=title, body=body)
    log.info(
        "Notified: port change on %s (%s) — +%d opened, -%d closed",
        mac, ip, len(opened), len(closed),
    )
