"""
scheduler.py — orchestrates periodic scans and DB persistence.

Responsibilities:
  - Run run_scan() on schedule (APScheduler)
  - Persist results to DB (Scan + ScanDevice + KnownDevice)
  - Diff against previous scan → detect new/gone devices
  - Fire notifications
  - Expose run_scan_now() for on-demand triggering from API
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

from config import config
from models import Scan, ScanDevice, KnownDevice, DeviceRttHistory, DeviceEvent, SessionLocal
from scanner import run_scan, DeviceResult, sse_emit
from notifier import notify_new_device, notify_device_gone, notify_scan_summary, notify_scan_error, notify_ports_changed

log = logging.getLogger("scheduler")

_scheduler: Optional[AsyncIOScheduler] = None
_scan_running: bool = False


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _save_scan(devices: list[DeviceResult], subnets: list[str], started_at: Optional[datetime] = None) -> int:
    """Persist a completed scan to DB, update KnownDevices, return scan_id."""
    now = datetime.utcnow()
    with SessionLocal() as db:
        db: Session

        # Create Scan record
        scan = Scan(
            started_at=started_at or now,
            finished_at=now,
            status="done",
            subnets=json.dumps(subnets),
            host_count=len(devices),
        )
        db.add(scan)
        db.flush()  # get scan.id

        new_devices: list[tuple[str, str, Optional[str], Optional[str]]] = []  # (mac, ip, hostname, alias)
        current_macs: set[str] = set()
        # (mac, ip, alias, opened_ports, closed_ports)
        port_changes: list[tuple[str, str, Optional[str], list[dict], list[dict]]] = []

        # In-session KnownDevice cache: avoids duplicate INSERT when the same MAC
        # appears twice in one scan (e.g. IPv4 + IPv6 both listed for a new device).
        # The IPv4 entry creates the KnownDevice; the IPv6 entry reuses it via this cache.
        known_cache: dict[str, KnownDevice] = {}

        for d in devices:
            ports_json = json.dumps([
                {"port": p.port, "proto": p.proto, "state": p.state,
                 "service": p.service, "version": p.version}
                for p in d.ports
            ])

            # Insert ScanDevice
            sd = ScanDevice(
                scan_id=scan.id,
                ip=d.ip,
                mac=d.mac,
                hostname=d.hostname,
                subnet=d.subnet,
                iface=d.iface,
                rtt_ms=d.rtt_ms,
                role=d.role,
                ports=ports_json,
                os_guess=d.os_guess,
                vendor=d.vendor,
                model=d.model,
                services=json.dumps(d.services) if d.services else None,
                tags=json.dumps(d.tags) if d.tags else None,
            )
            db.add(sd)

            # Update KnownDevice registry
            if d.mac:
                current_macs.add(d.mac)
                is_ipv6_entry = ":" in d.ip

                # Check in-session cache first to avoid duplicate INSERTs when
                # the same MAC appears as both IPv4 and IPv6 in the same scan.
                known = known_cache.get(d.mac)
                if known is None:
                    known = db.query(KnownDevice).filter_by(mac=d.mac).first()

                if known is None:
                    known = KnownDevice(
                        mac=d.mac,
                        first_seen=datetime.utcnow(),
                    )
                    db.add(known)
                    db.flush()  # make it visible within this session immediately
                    known_cache[d.mac] = known
                    new_devices.append((d.mac, d.ip, d.hostname, known.alias))
                else:
                    known_cache[d.mac] = known
                    # ── Port change detection (IPv4 entries only) ──────────────
                    # Skip port-change diff for IPv6 entries — the IPv4 pass already
                    # has authoritative port data; IPv6 entries often have no ports.
                    if not is_ipv6_entry and known.last_ports:
                        try:
                            prev_set = {
                                (p["port"], p.get("proto", "tcp"))
                                for p in json.loads(known.last_ports)
                            }
                            curr_list = json.loads(ports_json)
                            curr_set = {
                                (p["port"], p.get("proto", "tcp"))
                                for p in curr_list
                            }
                            opened_keys = curr_set - prev_set
                            closed_keys = prev_set - curr_set
                            if opened_keys or closed_keys:
                                curr_by_key = {
                                    (p["port"], p.get("proto", "tcp")): p
                                    for p in curr_list
                                }
                                prev_by_key = {
                                    (p["port"], p.get("proto", "tcp")): p
                                    for p in json.loads(known.last_ports)
                                }
                                port_changes.append((
                                    d.mac, d.ip, known.alias,
                                    [curr_by_key[k] for k in opened_keys],
                                    [prev_by_key[k] for k in closed_keys],
                                ))
                        except (json.JSONDecodeError, KeyError, TypeError):
                            pass

                known.last_seen = datetime.utcnow()
                # Don't overwrite a good IPv4 last_ip with an IPv6 address
                if not is_ipv6_entry or not known.last_ip or ":" not in known.last_ip:
                    if not is_ipv6_entry:
                        known.last_ip = d.ip
                    elif known.last_ip is None:
                        known.last_ip = d.ip
                known.last_hostname = d.hostname or known.last_hostname
                # Only update port/OS/model from IPv4 entries (richer data)
                if not is_ipv6_entry:
                    known.last_ports = ports_json
                    known.last_os = d.os_guess or known.last_os
                    known.last_vendor = d.vendor or known.last_vendor
                    known.last_model = d.model or known.last_model
                    known.last_services = json.dumps(d.services) if d.services else known.last_services
                    known.last_role = d.role or known.last_role
                else:
                    # IPv6 entry: only fill in gaps, never overwrite IPv4 data
                    if not known.last_vendor and d.vendor:
                        known.last_vendor = d.vendor

            # Apply user role override if set
            if d.mac and known is not None and known.role_override:
                d.role = known.role_override
                sd.role = known.role_override

            # ── RTT history entry (every device with a MAC) ────────────────────
            if d.mac:
                db.add(DeviceRttHistory(
                    mac=d.mac,
                    scan_id=scan.id,
                    scanned_at=now,
                    rtt_ms=d.rtt_ms,
                    is_up=True,
                ))

        db.commit()
        scan_id = scan.id

    # Diff: detect devices that disappeared (seen in prev scan, absent now)
    _detect_gone_devices(current_macs, new_devices, port_changes, subnets, len(devices), scan_id, now)

    return scan_id


def _detect_gone_devices(
    current_macs: set[str],
    new_devices: list,
    port_changes: list,
    subnets: list[str],
    total_hosts: int,
    scan_id: int,
    scanned_at: datetime,
) -> None:
    """Compare current scan MACs against last known set. Persist events and fire notifications."""
    new_device_macs = {mac for mac, _ip, _host, _alias in new_devices}

    with SessionLocal() as db:
        # Get MACs seen in the previous scan (last scan before this one)
        all_scans = db.query(Scan).order_by(Scan.id.desc()).limit(2).all()
        if len(all_scans) < 2:
            # First scan — persist new-device events only
            _persist_events(db, scan_id, scanned_at, new_devices, [], [], port_changes)
            db.commit()
            _fire_notifications(new_devices, [], port_changes, subnets, total_hosts)
            return

        prev_scan = all_scans[1]
        prev_macs = {
            sd.mac for sd in db.query(ScanDevice).filter_by(scan_id=prev_scan.id).all()
            if sd.mac
        }

        # Devices in prev scan not in current scan → disappeared
        gone_macs = prev_macs - current_macs

        # Devices in current scan not in prev scan, but already known → reappeared
        reappeared_macs = (current_macs - prev_macs) - new_device_macs

        gone_devices = []
        for mac in gone_macs:
            known = db.query(KnownDevice).filter_by(mac=mac).first()
            if known:
                gone_devices.append((mac, known.last_ip or "?", known.alias))
                db.add(DeviceRttHistory(
                    mac=mac,
                    scan_id=scan_id,
                    scanned_at=scanned_at,
                    rtt_ms=None,
                    is_up=False,
                ))

        reappeared_devices = []
        for mac in reappeared_macs:
            known = db.query(KnownDevice).filter_by(mac=mac).first()
            if known:
                # get current scan device for ip/hostname
                sd = db.query(ScanDevice).filter_by(scan_id=scan_id, mac=mac).first()
                reappeared_devices.append((
                    mac,
                    sd.ip if sd else (known.last_ip or "?"),
                    sd.hostname if sd else known.last_hostname,
                    known.alias,
                    known.last_vendor,
                    known.role_override or (sd.role if sd else None),
                ))

        _persist_events(db, scan_id, scanned_at, new_devices, gone_devices, reappeared_devices, port_changes)
        db.commit()

    _fire_notifications(new_devices, gone_devices, port_changes, subnets, total_hosts)


def _persist_events(
    db,
    scan_id: int,
    scanned_at: datetime,
    new_devices: list,
    gone_devices: list,
    reappeared_devices: list,
    port_changes: list,
) -> None:
    """Write DeviceEvent rows for this scan."""
    for mac, ip, hostname, alias in new_devices:
        known = db.query(KnownDevice).filter_by(mac=mac).first()
        db.add(DeviceEvent(
            scan_id=scan_id,
            created_at=scanned_at,
            event_type="new",
            mac=mac, ip=ip, hostname=hostname, alias=alias,
            extra=json.dumps({
                "vendor":   known.last_vendor if known else None,
                "role":     known.role_override if known else None,
            }),
        ))

    for mac, last_ip, alias in gone_devices:
        known = db.query(KnownDevice).filter_by(mac=mac).first()
        db.add(DeviceEvent(
            scan_id=scan_id,
            created_at=scanned_at,
            event_type="disappeared",
            mac=mac, ip=last_ip, hostname=known.last_hostname if known else None, alias=alias,
            extra=json.dumps({"vendor": known.last_vendor if known else None}),
        ))

    for mac, ip, hostname, alias, vendor, role in reappeared_devices:
        db.add(DeviceEvent(
            scan_id=scan_id,
            created_at=scanned_at,
            event_type="reappeared",
            mac=mac, ip=ip, hostname=hostname, alias=alias,
            extra=json.dumps({"vendor": vendor, "role": role}),
        ))

    for mac, ip, alias, opened, closed in port_changes:
        known = db.query(KnownDevice).filter_by(mac=mac).first()
        db.add(DeviceEvent(
            scan_id=scan_id,
            created_at=scanned_at,
            event_type="ports_changed",
            mac=mac, ip=ip, hostname=known.last_hostname if known else None, alias=alias,
            extra=json.dumps({"opened": opened, "closed": closed}),
        ))


def _fire_notifications(new_devices, gone_devices, port_changes, subnets, total_hosts):
    """Schedule async notifications without blocking the calling thread."""
    async def _notify():
        for mac, ip, hostname, alias in new_devices:
            await notify_new_device(mac, ip, hostname, alias)
        for mac, last_ip, alias in gone_devices:
            await notify_device_gone(mac, last_ip, alias)
        for mac, ip, alias, opened, closed in port_changes:
            await notify_ports_changed(mac, ip, alias, opened, closed)
        await notify_scan_summary(
            total_hosts, len(new_devices), len(gone_devices), subnets,
            port_change_count=len(port_changes),
        )

    asyncio.ensure_future(_notify())


# ── Scan job ───────────────────────────────────────────────────────────────────

async def _scan_job() -> None:
    global _scan_running
    if _scan_running:
        log.warning("Scan already in progress — skipping scheduled run.")
        return
    _scan_running = True
    started_at = datetime.utcnow()
    log.info("Starting scheduled scan...")

    try:
        devices, iface_count = await run_scan()
        # Save to DB first (synchronous, blocks event loop briefly — but that is fine
        # because the SSE 'done' is emitted AFTER this call, so the frontend only
        # learns the scan is complete once the data is actually committed to DB).
        subnets = list({d.subnet for d in devices})
        scan_id = _save_scan(devices, subnets, started_at)
        log.info("Scan #%d saved: %d hosts on %d subnets.", scan_id, len(devices), len(subnets))
    except Exception as e:
        log.exception("Scan failed: %s", e)
        await notify_scan_error(str(e))
        await sse_emit({"type": "error", "msg": f"Scan failed: {e}"})
        return
    finally:
        _scan_running = False

    # Emit 'done' only after DB commit — the frontend will call loadLastScan()
    # immediately on receiving this event, so the data must already be persisted.
    await sse_emit({
        "type": "done",
        "total": len(devices),
        "msg": f"Scan complete. {len(devices)} hosts enumerated across {iface_count} subnet(s).",
    })


async def run_scan_now() -> dict:
    """Trigger an immediate scan. Returns status dict."""
    if _scan_running:
        return {"status": "already_running"}
    asyncio.ensure_future(_scan_job())
    return {"status": "started"}


def is_scan_running() -> bool:
    return _scan_running


# ── Scheduler lifecycle ────────────────────────────────────────────────────────

def start_scheduler() -> None:
    global _scheduler
    if config.SCAN_INTERVAL_MINUTES <= 0:
        log.info("Auto-scan disabled (SCAN_INTERVAL_MINUTES=0).")
        return

    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(
        _scan_job,
        trigger=IntervalTrigger(minutes=config.SCAN_INTERVAL_MINUTES),
        id="auto_scan",
        name="Periodic LAN scan",
        replace_existing=True,
        max_instances=1,
    )
    _scheduler.start()
    log.info("Scheduler started: scan every %d minutes.", config.SCAN_INTERVAL_MINUTES)


def stop_scheduler() -> None:
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        log.info("Scheduler stopped.")
