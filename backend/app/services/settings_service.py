"""
RESILIX Settings Service
Manages runtime-configurable application settings stored in SQLite (`application_settings`).
"""
import json
from typing import Any

from app.config import settings
from app.database import DatabaseSession, utc_now_iso

DEFAULT_RUNTIME_SETTINGS: dict[str, Any] = {
    "app_name": settings.app_name,
    "stale_data_timeout_seconds": 30,
    "default_persistence_window": 2,
    "simulator_interval_seconds": 2.0,
    "max_simulator_speed": 10.0,
    "event_retention_limit": 5000,
    "sync_max_retries": 5,
    "sync_backoff_base_seconds": 2.0,
    "dashboard_refresh_seconds": 4,
    "baseline_window_size": 25,
    "baseline_min_samples": 5,
}


def get_runtime_settings(db: DatabaseSession) -> dict[str, Any]:
    result = dict(DEFAULT_RUNTIME_SETTINGS)
    rows = db.fetchall("SELECT key, value_json FROM application_settings")
    for row in rows:
        try:
            result[row["key"]] = json.loads(row["value_json"])
        except Exception:
            pass
    return result


def update_runtime_settings(
    db: DatabaseSession,
    updates: dict[str, Any],
    actor_username: str = "admin",
) -> dict[str, Any]:
    now_iso = utc_now_iso()
    for key, val in updates.items():
        if val is None or key == "device_thresholds":
            continue
        db.execute(
            """
            INSERT INTO application_settings (key, value_json, updated_by, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            (key, json.dumps(val), actor_username, now_iso),
        )

    device_thresholds = updates.get("device_thresholds")
    if isinstance(device_thresholds, dict):
        for dev_id, cfg in device_thresholds.items():
            if not isinstance(cfg, dict):
                continue
            existing = db.fetchone("SELECT * FROM equipment WHERE device_id = ?", (dev_id,))
            if not existing:
                continue
            temp_warn = float(cfg.get("temp_warning_threshold", existing["temp_warning_threshold"]))
            temp_crit = float(cfg.get("temp_critical_threshold", existing["temp_critical_threshold"]))
            vib_warn = float(cfg.get("vib_warning_threshold", existing["vib_warning_threshold"]))
            vib_crit = float(cfg.get("vib_critical_threshold", existing["vib_critical_threshold"]))
            cur_warn = float(cfg.get("current_warning_threshold", existing["current_warning_threshold"]))
            cur_crit = float(cfg.get("current_critical_threshold", existing["current_critical_threshold"]))
            p_win = int(cfg.get("persistence_window_count", existing["persistence_window_count"]))
            has_cur = 1 if cfg.get("has_current_sensor", bool(existing["has_current_sensor"])) else 0

            if temp_warn >= temp_crit:
                raise ValueError(f"{dev_id}: temp_warning_threshold must be less than temp_critical_threshold")
            if vib_warn >= vib_crit:
                raise ValueError(f"{dev_id}: vib_warning_threshold must be less than vib_critical_threshold")
            if cur_warn >= cur_crit:
                raise ValueError(f"{dev_id}: current_warning_threshold must be less than current_critical_threshold")
            if p_win < 1 or p_win > 15:
                raise ValueError(f"{dev_id}: persistence_window_count must be between 1 and 15")

            db.execute(
                """
                UPDATE equipment SET
                    temp_warning_threshold = ?,
                    temp_critical_threshold = ?,
                    vib_warning_threshold = ?,
                    vib_critical_threshold = ?,
                    current_warning_threshold = ?,
                    current_critical_threshold = ?,
                    persistence_window_count = ?,
                    has_current_sensor = ?,
                    updated_at = ?
                WHERE device_id = ?
                """,
                (
                    temp_warn,
                    temp_crit,
                    vib_warn,
                    vib_crit,
                    cur_warn,
                    cur_crit,
                    p_win,
                    has_cur,
                    now_iso,
                    dev_id,
                ),
            )

    return get_runtime_settings(db)
