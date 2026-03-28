import os


class Config:
    # Database
    DB_PATH: str = os.getenv("DB_PATH", "/data/netsonar.db")
    DB_URL: str = f"sqlite:///{DB_PATH}"

    # Scheduler
    SCAN_INTERVAL_MINUTES: int = int(os.getenv("SCAN_INTERVAL_MINUTES", "15"))
    RETENTION_DAYS: int = int(os.getenv("RETENTION_DAYS", "730"))
    SCAN_TIMEOUT_MS: int = int(os.getenv("SCAN_TIMEOUT_MS", "500"))
    NMAP_EXTRA_ARGS: str = os.getenv("NMAP_EXTRA_ARGS", "")

    # SNMP
    SNMP_COMMUNITY: str = os.getenv("SNMP_COMMUNITY", "public")

    # Notifications
    NOTIFY_ENABLED: bool = os.getenv("NOTIFY_ENABLED", "false").lower() == "true"
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASS: str = os.getenv("SMTP_PASS", "")
    NOTIFY_FROM: str = os.getenv("NOTIFY_FROM", "")
    NOTIFY_TO: str = os.getenv("NOTIFY_TO", "")


config = Config()
