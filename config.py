"""
NetGuard configuration.
All values come from environment variables so secrets never live in source
control. See .env.example for the full list.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # --- Flask ---
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-.env")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    # --- MySQL ---
    MYSQL_HOST = os.getenv("MYSQL_HOST", "db")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
    MYSQL_USER = os.getenv("MYSQL_USER", "netguard")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "netguard_pw")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "netguard")

    # --- NVD CVE API (optional key = higher rate limit) ---
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # --- Scanner behaviour ---
    # Hard allow-list guard: scans are only permitted against targets the
    # operator explicitly added to ALLOWED_TARGETS (CIDR, hostname, or IP),
    # to keep this tool pointed only at infrastructure you are authorized
    # to test. Edit via the web UI (table `allowed_targets`) or this env var.
    ALLOWED_TARGETS = [t.strip() for t in os.getenv("ALLOWED_TARGETS", "127.0.0.1,localhost").split(",") if t.strip()]
    DEFAULT_PORT_RANGE = os.getenv("DEFAULT_PORT_RANGE", "1-1024")
    SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))

    REPORTS_DIR = os.getenv("REPORTS_DIR", "/app/reports")
