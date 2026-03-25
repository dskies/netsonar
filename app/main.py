"""
main.py — FastAPI application entry point.

API routes:
  GET  /                          → serve SPA (index.html)
  GET  /api/scans                 → list of past scans (paginated)
  GET  /api/scans/{id}            → single scan detail with devices
  GET  /api/scans/{id}/devices    → devices of a scan (paginated, filterable)
  GET  /api/scans/diff/{id_a}/{id_b} → diff two scans
  POST /api/scan                  → trigger scan now
  GET  /api/scan/stream           → SSE live scan progress
  GET  /api/devices               → known device registry
  PATCH /api/devices/{mac}        → update alias/notes/trusted for a device
  GET  /api/status                → app status (running scan, interval, etc.)
  GET  /api/config                → current config (non-secret fields)
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, AsyncGenerator

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import config
from models import init_db, get_db, Scan, ScanDevice, KnownDevice, DeviceRttHistory, DeviceEvent
from risk import score_device as risk_score_device
from scheduler import start_scheduler, stop_scheduler, run_scan_now, is_scan_running
from scanner import sse_stream, get_partial_devices

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
log = logging.getLogger("main")

app = FastAPI(title="NetSonar", version="1.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Lifecycle ──────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_db()
    start_scheduler()
    log.info("NetSonar started. Dashboard at http://0.0.0.0:8080/")


@app.on_event("shutdown")
async def shutdown():
    stop_scheduler()


# ── Static files (SPA) ─────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()


# ── Status ─────────────────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status(db: Session = Depends(get_db)):
    last_scan = db.query(Scan).order_by(Scan.id.desc()).first()

    # Next scheduled scan time from APScheduler
    next_scan_at: Optional[str] = None
    try:
        from scheduler import _scheduler
        if _scheduler is not None:
            job = _scheduler.get_job("auto_scan")
            if job and job.next_run_time:
                next_scan_at = job.next_run_time.isoformat()
    except Exception:
        pass

    duration_s: Optional[float] = None
    if last_scan and last_scan.finished_at and last_scan.started_at:
        duration_s = round((last_scan.finished_at - last_scan.started_at).total_seconds())

    return {
        "scan_running": is_scan_running(),
        "scan_interval_minutes": config.SCAN_INTERVAL_MINUTES,
        "notify_enabled": config.NOTIFY_ENABLED,
        "next_scan_at": next_scan_at,
        "unread_notifications": db.query(DeviceEvent).count(),
        "last_scan": {
            "id": last_scan.id,
            "started_at": last_scan.started_at.isoformat() if last_scan else None,
            "finished_at": last_scan.finished_at.isoformat() if last_scan.finished_at else None,
            "duration_s": duration_s,
            "host_count": last_scan.host_count,
            "status": last_scan.status,
        } if last_scan else None,
    }


# ── Scan trigger + SSE stream ─────────────────────────────────────────────────

@app.post("/api/scan")
async def trigger_scan():
    result = await run_scan_now()
    return result


@app.get("/api/scan/stream")
async def scan_stream():
    """Server-Sent Events stream for live scan progress."""
    async def event_generator() -> AsyncGenerator[str, None]:
        async for msg in sse_stream():
            yield f"data: {json.dumps(msg)}\n\n"
            if msg.get("type") in ("done", "error"):
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/scan/partial")
async def scan_partial():
    """Return full live scan state for page-reload recovery."""
    return get_partial_devices()


# ── Scans history ─────────────────────────────────────────────────────────────

@app.get("/api/scans")
async def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    total = db.query(Scan).count()
    scans = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [_fmt_scan(s) for s in scans],
    }


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    devices = db.query(ScanDevice).filter_by(scan_id=scan_id).all()
    return {**_fmt_scan(scan), "devices": [_fmt_device(d) for d in devices]}


@app.get("/api/scans/{scan_id}/devices")
async def get_scan_devices(
    scan_id: int,
    subnet: Optional[str] = None,
    role: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(ScanDevice).filter_by(scan_id=scan_id)
    if subnet:
        q = q.filter(ScanDevice.subnet == subnet)
    if role:
        q = q.filter(ScanDevice.role == role)
    if search:
        like = f"%{search}%"
        q = q.filter(
            ScanDevice.ip.like(like) |
            ScanDevice.mac.like(like) |
            ScanDevice.hostname.like(like)
        )
    total = q.count()
    devices = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [_fmt_device(d) for d in devices],
    }


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}


@app.get("/api/scans/diff/{id_a}/{id_b}")
async def diff_scans(id_a: int, id_b: int, db: Session = Depends(get_db)):
    """Compare two scans: new/gone/changed devices."""
    scan_a = db.query(Scan).filter_by(id=id_a).first()
    scan_b = db.query(Scan).filter_by(id=id_b).first()
    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    devs_a = {d.mac or d.ip: d for d in db.query(ScanDevice).filter_by(scan_id=id_a).all()}
    devs_b = {d.mac or d.ip: d for d in db.query(ScanDevice).filter_by(scan_id=id_b).all()}

    keys_a, keys_b = set(devs_a), set(devs_b)
    appeared = [_fmt_device(devs_b[k]) for k in (keys_b - keys_a)]
    disappeared = [_fmt_device(devs_a[k]) for k in (keys_a - keys_b)]
    changed = []
    for k in keys_a & keys_b:
        da, db_ = devs_a[k], devs_b[k]
        if da.ip != db_.ip or da.hostname != db_.hostname:
            changed.append({"before": _fmt_device(da), "after": _fmt_device(db_)})

    return {
        "scan_a": _fmt_scan(scan_a),
        "scan_b": _fmt_scan(scan_b),
        "appeared": appeared,
        "disappeared": disappeared,
        "changed": changed,
    }


# ── Risk assessment ───────────────────────────────────────────────────────────

@app.get("/api/risk")
async def get_risk_assessment(db: Session = Depends(get_db)):
    """Compute offline risk scores for all known devices and return summary + per-device results."""
    devices = db.query(KnownDevice).order_by(KnownDevice.last_seen.desc()).all()

    results = []
    for d in devices:
        effective_role = d.role_override or d.last_role or "Host"
        scored = risk_score_device(
            mac=d.mac,
            last_ip=d.last_ip,
            last_hostname=d.last_hostname,
            alias=d.alias,
            last_ports_json=d.last_ports,
            last_os=d.last_os,
            last_vendor=d.last_vendor,
            last_model=d.last_model,
            last_services_json=d.last_services,
            role=effective_role,
            is_trusted=bool(d.is_trusted),
        )
        results.append({
            "mac":           d.mac,
            "last_ip":       d.last_ip,
            "last_hostname": d.last_hostname,
            "alias":         d.alias,
            "last_vendor":   d.last_vendor,
            "last_model":    d.last_model,
            "last_role":     effective_role,
            "is_trusted":    bool(d.is_trusted),
            "last_seen":     d.last_seen.isoformat() if d.last_seen else None,
            **scored,
        })

    # Sort by score descending
    results.sort(key=lambda r: r["score"], reverse=True)

    # Summary counters
    level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
    for r in results:
        level_counts[r["level"]] = level_counts.get(r["level"], 0) + 1

    # Overall network risk score: weighted average skewed by top scores
    if results:
        top_scores = sorted([r["score"] for r in results], reverse=True)
        # Top-3 devices contribute 60% of the network score, rest 40%
        top3 = top_scores[:3]
        rest = top_scores[3:]
        net_score = int(
            (
                (sum(top3) / len(top3) * 0.6 if top3 else 0) +
                (sum(rest) / len(rest) * 0.4 if rest else 0)
            )
        ) if len(results) > 3 else int(sum(top_scores) / len(top_scores)) if top_scores else 0
    else:
        net_score = 0

    return {
        "network_score":  net_score,
        "device_count":   len(results),
        "level_counts":   level_counts,
        "devices":        results,
    }


# ── Notifications ─────────────────────────────────────────────────────────────

@app.get("/api/notifications")
async def list_notifications(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(DeviceEvent).order_by(DeviceEvent.id.desc())
    if event_type and event_type != "all":
        q = q.filter(DeviceEvent.event_type == event_type)
    total = q.count()
    events = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [_fmt_event(e) for e in events],
    }


# ── Known device registry ─────────────────────────────────────────────────────

@app.get("/api/devices")
async def list_known_devices(
    search: Optional[str] = None,
    trusted_only: bool = False,
    db: Session = Depends(get_db),
):
    q = db.query(KnownDevice).order_by(KnownDevice.last_seen.desc())
    if trusted_only:
        q = q.filter_by(is_trusted=True)
    if search:
        like = f"%{search}%"
        q = q.filter(
            KnownDevice.mac.like(like) |
            KnownDevice.alias.like(like) |
            KnownDevice.last_ip.like(like) |
            KnownDevice.last_hostname.like(like)
        )
    devices = q.all()
    return [_fmt_known(d) for d in devices]


class DevicePatch(BaseModel):
    alias: Optional[str] = None
    notes: Optional[str] = None
    is_trusted: Optional[bool] = None
    role_override: Optional[str] = None


@app.delete("/api/devices/{mac}")
async def delete_device(mac: str, db: Session = Depends(get_db)):
    mac = mac.upper().replace("-", ":").strip()
    device = db.query(KnownDevice).filter_by(mac=mac).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return {"deleted": mac}


@app.patch("/api/devices/{mac}")
async def patch_device(mac: str, patch: DevicePatch, db: Session = Depends(get_db)):
    # Normalize MAC format
    mac = mac.upper().replace("-", ":").strip()
    device = db.query(KnownDevice).filter_by(mac=mac).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if patch.alias is not None:
        device.alias = patch.alias.strip()[:128]
    if patch.notes is not None:
        device.notes = patch.notes.strip()[:2000]
    if patch.is_trusted is not None:
        device.is_trusted = patch.is_trusted
    if patch.role_override is not None:
        # empty string means "clear override"
        device.role_override = patch.role_override.strip()[:32] or None
    db.commit()
    return _fmt_known(device)


@app.get("/api/devices/{mac}/history")
async def get_device_history(
    mac: str,
    limit: int = Query(60, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """
    Return RTT and availability history for a single device.
    Results are in chronological order (oldest first).
    Also returns summary stats: total measurements and uptime_pct.
    """
    mac = mac.upper().replace("-", ":").strip()
    total = db.query(DeviceRttHistory).filter_by(mac=mac).count()
    up_count = (
        db.query(DeviceRttHistory)
        .filter(DeviceRttHistory.mac == mac, DeviceRttHistory.is_up.is_(True))
        .count()
    )
    records = (
        db.query(DeviceRttHistory)
        .filter_by(mac=mac)
        .order_by(DeviceRttHistory.scanned_at.desc())
        .limit(limit)
        .all()
    )
    items = [
        {
            "scan_id":    r.scan_id,
            "scanned_at": r.scanned_at.isoformat(),
            "rtt_ms":     r.rtt_ms,
            "is_up":      bool(r.is_up),
        }
        for r in reversed(records)  # chronological order
    ]
    return {
        "mac":        mac,
        "total":      total,
        "uptime_pct": round(up_count / total * 100, 1) if total > 0 else None,
        "items":      items,
    }


# ── Formatters ─────────────────────────────────────────────────────────────────

def _fmt_event(e: DeviceEvent) -> dict:
    return {
        "id":         e.id,
        "scan_id":    e.scan_id,
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "event_type": e.event_type,
        "mac":        e.mac,
        "ip":         e.ip,
        "hostname":   e.hostname,
        "alias":      e.alias,
        "extra":      json.loads(e.extra) if e.extra else {},
    }


def _fmt_scan(s: Scan) -> dict:
    return {
        "id": s.id,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "status": s.status,
        "subnets": json.loads(s.subnets) if s.subnets else [],
        "host_count": s.host_count,
    }


def _fmt_device(d: ScanDevice) -> dict:
    ports = []
    if d.ports:
        try:
            ports = json.loads(d.ports)
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "id": d.id,
        "scan_id": d.scan_id,
        "ip": d.ip,
        "mac": d.mac,
        "hostname": d.hostname,
        "subnet": d.subnet,
        "iface": d.iface,
        "rtt_ms": d.rtt_ms,
        "role": d.role,
        "ports": ports,
        "os_guess": d.os_guess,
        "vendor": d.vendor,
        "model": d.model,
        "services": json.loads(d.services) if d.services else [],
        "tags": json.loads(d.tags) if d.tags else [],
    }


def _fmt_known(d: KnownDevice) -> dict:
    ports = []
    if d.last_ports:
        try:
            ports = json.loads(d.last_ports)
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "mac": d.mac,
        "alias": d.alias,
        "notes": d.notes,
        "first_seen": d.first_seen.isoformat() if d.first_seen else None,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "last_ip": d.last_ip,
        "last_hostname": d.last_hostname,
        "is_trusted": d.is_trusted,
        "role_override": d.role_override,
        "last_ports": ports,
        "last_os": d.last_os,
        "vendor": d.last_vendor,
        "model": d.last_model,
        "services": json.loads(d.last_services) if d.last_services else [],
        "last_role": d.last_role,
    }
