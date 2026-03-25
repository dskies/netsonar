from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Float,
    DateTime, Boolean, Text, ForeignKey, Index, text
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker
from config import config




class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One full network scan run."""
    __tablename__ = "scans"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    started_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    status      = Column(String(16), default="running")  # running | done | error
    subnets     = Column(Text, nullable=True)             # JSON list of scanned CIDRs
    host_count  = Column(Integer, default=0)
    error_msg   = Column(Text, nullable=True)

    devices = relationship("ScanDevice", back_populates="scan", cascade="all, delete-orphan")


class ScanDevice(Base):
    """A device found in a specific scan."""
    __tablename__ = "scan_devices"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    scan_id   = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    ip        = Column(String(45), nullable=False)
    mac       = Column(String(17), nullable=True)
    hostname  = Column(String(255), nullable=True)
    subnet    = Column(String(43), nullable=True)
    iface     = Column(String(64), nullable=True)
    rtt_ms    = Column(Float, nullable=True)
    role      = Column(String(32), nullable=True)
    # Port scan results stored as JSON string: [{"port":80,"proto":"tcp","state":"open","service":"http"}, ...]
    ports     = Column(Text, nullable=True)
    os_guess  = Column(String(128), nullable=True)
    vendor    = Column(String(128), nullable=True)
    model     = Column(String(128), nullable=True)
    services  = Column(Text, nullable=True)      # JSON list of service strings
    tags      = Column(Text, nullable=True)      # JSON list e.g. ["DNS1", "DHCP"]

    scan = relationship("Scan", back_populates="devices")

    __table_args__ = (
        Index("ix_scan_devices_scan_id", "scan_id"),
        Index("ix_scan_devices_ip", "ip"),
        Index("ix_scan_devices_mac", "mac"),
    )


class KnownDevice(Base):
    """
    Persistent device registry, keyed by MAC address.
    Survives across scans; used to detect new/gone devices and store human labels.
    """
    __tablename__ = "known_devices"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    mac          = Column(String(17), unique=True, nullable=False)
    alias        = Column(String(128), nullable=True)          # user-assigned friendly name
    notes        = Column(Text, nullable=True)
    first_seen   = Column(DateTime, default=datetime.utcnow)
    last_seen    = Column(DateTime, default=datetime.utcnow)
    last_ip      = Column(String(45), nullable=True)
    last_hostname= Column(String(255), nullable=True)
    is_trusted   = Column(Boolean, default=False)              # user marks as known/trusted
    role_override = Column(String(32), nullable=True)           # user-forced role (overrides auto-detect)
    # Latest port scan results (JSON), updated each scan
    last_ports   = Column(Text, nullable=True)
    last_os      = Column(String(128), nullable=True)
    last_vendor  = Column(String(128), nullable=True)
    last_model   = Column(String(128), nullable=True)
    last_services= Column(Text, nullable=True)   # JSON list of service strings
    last_role    = Column(String(32), nullable=True)  # auto-detected role from latest scan

    __table_args__ = (
        Index("ix_known_devices_mac", "mac"),
    )


class DeviceRttHistory(Base):
    """
    RTT and availability timeseries per device, keyed by MAC.
    One row per device per completed scan — provides the data for latency
    sparklines and uptime-percentage calculations in the UI.
    """
    __tablename__ = "device_rtt_history"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    mac        = Column(String(17), nullable=False)
    scan_id    = Column(Integer, nullable=False)
    scanned_at = Column(DateTime, nullable=False)
    rtt_ms     = Column(Float, nullable=True)
    is_up      = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_rtt_hist_mac_time", "mac", "scanned_at"),
        Index("ix_rtt_hist_scan_id",  "scan_id"),
    )


class DeviceEvent(Base):
    """
    Persistent log of notable device events detected between consecutive scans.
    event_type: new | disappeared | reappeared | ports_changed
    """
    __tablename__ = "device_events"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    scan_id    = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    event_type = Column(String(32), nullable=False)
    mac        = Column(String(17), nullable=True)
    ip         = Column(String(45), nullable=True)
    hostname   = Column(String(255), nullable=True)
    alias      = Column(String(128), nullable=True)
    extra      = Column(Text, nullable=True)   # JSON: e.g. opened/closed ports, vendor, role

    __table_args__ = (
        Index("ix_device_events_scan_id",    "scan_id"),
        Index("ix_device_events_created_at", "created_at"),
        Index("ix_device_events_mac",        "mac"),
    )


# ── DB init ────────────────────────────────────────────────────────────────────

engine = create_engine(
    config.DB_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # Safe schema migration: add tags column to existing databases
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE scan_devices ADD COLUMN tags TEXT"))
            conn.commit()
        except Exception:
            pass  # Column already exists
        try:
            conn.execute(text("ALTER TABLE known_devices ADD COLUMN role_override TEXT"))
            conn.commit()
        except Exception:
            pass  # Column already exists
        # Migration: create device_rtt_history if it was added after initial deploy
        try:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS device_rtt_history ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  mac TEXT NOT NULL,"
                "  scan_id INTEGER NOT NULL,"
                "  scanned_at DATETIME NOT NULL,"
                "  rtt_ms REAL,"
                "  is_up INTEGER NOT NULL DEFAULT 1"
                ")"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_rtt_hist_mac_time "
                "ON device_rtt_history (mac, scanned_at)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_rtt_hist_scan_id "
                "ON device_rtt_history (scan_id)"
            ))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE known_devices ADD COLUMN last_role TEXT"))
            conn.commit()
        except Exception:
            pass  # Column already exists
        # Migration: create device_events table if added after initial deploy
        try:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS device_events ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  scan_id INTEGER NOT NULL,"
                "  created_at DATETIME NOT NULL,"
                "  event_type TEXT NOT NULL,"
                "  mac TEXT,"
                "  ip TEXT,"
                "  hostname TEXT,"
                "  alias TEXT,"
                "  extra TEXT"
                ")"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_device_events_scan_id "
                "ON device_events (scan_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_device_events_created_at "
                "ON device_events (created_at)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_device_events_mac "
                "ON device_events (mac)"
            ))
            conn.commit()
        except Exception:
            pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
