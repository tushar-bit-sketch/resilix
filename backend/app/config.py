"""
RESILIX Configuration Module
Seva First Innovation Challenge 2026 | Surakshit Bharat — Security & Resilience
"""
import os
import secrets
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
# Use /tmp/resilix.db if the workspace sits on a 9p virtual mount that blocks SQLiteWAL shm mmap
_cand_dir = BASE_DIR
try:
    if not os.listdir(str(BASE_DIR)):
        _cand_dir = Path("/tmp")
except Exception:
    _cand_dir = Path("/tmp")
DEFAULT_DB_PATH = _cand_dir / "resilix.db"


class Settings(BaseModel):
    app_name: str = os.getenv("RESILIX_APP_NAME", "RESILIX")
    app_full_name: str = "Secure Predictive Infrastructure Resilience System"
    app_version: str = "1.0.0"
    environment: str = os.getenv("RESILIX_ENV", "development")
    database_path: str = os.getenv("RESILIX_DB_PATH", str(DEFAULT_DB_PATH))
    secret_key: str = os.getenv("RESILIX_SECRET_KEY", secrets.token_hex(32))
    session_ttl_minutes: int = int(os.getenv("RESILIX_SESSION_TTL_MINUTES", "480"))
    cors_origins: list[str] = [
        o.strip()
        for o in os.getenv(
            "RESILIX_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000",
        ).split(",")
        if o.strip()
    ]
    max_request_body_bytes: int = int(os.getenv("RESILIX_MAX_REQUEST_BYTES", "262144"))
    login_rate_limit_attempts: int = int(os.getenv("RESILIX_LOGIN_MAX_ATTEMPTS", "5"))
    login_rate_limit_window_seconds: int = int(os.getenv("RESILIX_LOGIN_WINDOW_SEC", "60"))
    genesis_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"


settings = Settings()
