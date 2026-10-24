"""
RESILIX Database Seeding & Demo-Data Reset Service
Seeds:
- Two demonstration accounts (stored as memory-hard Scrypt password hashes):
  1. Administrator: username `admin`, password `ResilixAdmin!2026`
  2. Operator:      username `operator`, password `ResilixOper!2026`
- Three realistic simulated laboratory test-rig devices:
  1. `PUMP-01`  — Water Pump Test Rig (Centrifugal Booster Pump, Lab Bay A)
  2. `MOTOR-02` — Laboratory Motor (3-Phase Induction Drive, Test Bench B)
  3. `FAN-03`   — Ventilation Fan (Industrial Exhaust Blower, Utility Duct C)
- Initial normal baseline telemetry readings (8 per device) so charts, rolling statistics,
  and initial genesis event chain are immediately populated and verifiable upon startup.
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from app.database import DatabaseSession, utc_now_iso
from app.models.schema import init_db_schema
from app.security.auth import hash_password, reset_all_rate_limits
from app.services.integrity import record_event_with_integrity
from app.services.settings_service import DEFAULT_RUNTIME_SETTINGS
from app.services.sync_service import run_synchronization_batch, set_sync_connectivity_state
from app.services.telemetry_processor import ingest_and_evaluate_telemetry
from app.simulator.engine import simulator_engine

DEMO_USERS = [
    {
        "username": "admin",
        "full_name": "Priya Nair (Infrastructure Security Admin)",
        "role": "admin",
        "password": "ResilixAdmin!2026",
    },
    {
        "username": "operator",
        "full_name": "Arjun Mehta (Plant Maintenance Operator)",
        "role": "operator",
        "password": "ResilixOper!2026",
    },
]

DEMO_EQUIPMENT = [
    {
        "device_id": "PUMP-01",
        "name": "Water Pump Test Rig",
        "device_type": "water_pump",
        "location": "Hydraulics Lab — Bay A1",
        "description": "Simulated 2.2 kW centrifugal water booster pump test rig with bearing accelerometer and stator thermistor.",
        "is_simulated": 1,
        "is_enabled": 1,
        "has_current_sensor": 1,
        "temp_normal_min": 36.0,
        "temp_normal_max": 48.0,
        "temp_warning_threshold": 56.0,
        "temp_critical_threshold": 66.0,
        "vib_normal_min": 1.1,
        "vib_normal_max": 2.8,
        "vib_warning_threshold": 4.2,
        "vib_critical_threshold": 6.5,
        "current_normal_min": 4.0,
        "current_normal_max": 6.2,
        "current_warning_threshold": 8.0,
        "current_critical_threshold": 10.5,
        "persistence_window_count": 2,
    },
    {
        "device_id": "MOTOR-02",
        "name": "Laboratory Motor",
        "device_type": "motor",
        "location": "Electromechanical Test Bench B2",
        "description": "Simulated 1.5 kW squirrel-cage induction motor test rig for load and thermal drift evaluation.",
        "is_simulated": 1,
        "is_enabled": 1,
        "has_current_sensor": 1,
        "temp_normal_min": 38.0,
        "temp_normal_max": 50.0,
        "temp_warning_threshold": 58.0,
        "temp_critical_threshold": 68.0,
        "vib_normal_min": 1.0,
        "vib_normal_max": 2.6,
        "vib_warning_threshold": 4.0,
        "vib_critical_threshold": 6.2,
        "current_normal_min": 3.5,
        "current_normal_max": 5.8,
        "current_warning_threshold": 7.8,
        "current_critical_threshold": 10.0,
        "persistence_window_count": 2,
    },
    {
        "device_id": "FAN-03",
        "name": "Ventilation Fan",
        "device_type": "fan",
        "location": "Utility Sub-Station Duct C3",
        "description": "Simulated axial ventilation exhaust fan unit monitored for blade imbalance and bearing wear.",
        "is_simulated": 1,
        "is_enabled": 1,
        "has_current_sensor": 1,
        "temp_normal_min": 34.0,
        "temp_normal_max": 45.0,
        "temp_warning_threshold": 54.0,
        "temp_critical_threshold": 64.0,
        "vib_normal_min": 1.2,
        "vib_normal_max": 3.0,
        "vib_warning_threshold": 4.5,
        "vib_critical_threshold": 7.0,
        "current_normal_min": 2.8,
        "current_normal_max": 4.8,
        "current_warning_threshold": 6.8,
        "current_critical_threshold": 9.0,
        "persistence_window_count": 2,
    },
]


def seed_initial_data(db: DatabaseSession, force_reset: bool = False) -> dict[str, Any]:
    """
    Idempotently seed demo users, equipment, settings, maintenance notes, and initial baseline
    telemetry. Does not overwrite or duplicate existing user data unless force_reset=True.
    """
    init_db_schema()
    now_iso = utc_now_iso()

    if force_reset:
        simulator_engine.reset_state()
        reset_all_rate_limits()
        for tbl in [
            "sync_acknowledgements",
            "sync_queue_items",
            "alerts",
            "event_integrity_records",
            "events",
            "sensor_readings",
            "maintenance_notes",
            "scenario_executions",
            "audit_logs",
            "application_settings",
            "equipment",
        ]:
            db.execute(f"DELETE FROM {tbl}")

    # 1. Seed Users (idempotent)
    for u in DEMO_USERS:
        existing_u = db.fetchone("SELECT id FROM users WHERE username = ?", (u["username"],))
        if not existing_u:
            pw_hash = hash_password(u["password"])
            db.execute(
                """
                INSERT INTO users (username, full_name, role, password_hash, is_active, created_at)
                VALUES (?, ?, ?, ?, 1, ?)
                """,
                (u["username"], u["full_name"], u["role"], pw_hash, now_iso),
            )

    # 2. Seed Application Settings (idempotent)
    for key, val in DEFAULT_RUNTIME_SETTINGS.items():
        existing_s = db.fetchone("SELECT key FROM application_settings WHERE key = ?", (key,))
        if not existing_s:
            db.execute(
                """
                INSERT INTO application_settings (key, value_json, updated_by, updated_at)
                VALUES (?, ?, 'system_seed', ?)
                """,
                (key, json.dumps(val), now_iso),
            )

    # 3. Seed Equipment (idempotent)
    seeded_devices = 0
    for eq in DEMO_EQUIPMENT:
        existing_eq = db.fetchone("SELECT device_id FROM equipment WHERE device_id = ?", (eq["device_id"],))
        if not existing_eq:
            seeded_devices += 1
            db.execute(
                """
                INSERT INTO equipment (
                    device_id, name, device_type, location, description,
                    is_simulated, is_enabled, operational_status, sensor_health_status,
                    has_current_sensor, temp_normal_min, temp_normal_max,
                    temp_warning_threshold, temp_critical_threshold,
                    vib_normal_min, vib_normal_max, vib_warning_threshold, vib_critical_threshold,
                    current_normal_min, current_normal_max, current_warning_threshold, current_critical_threshold,
                    persistence_window_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'HEALTHY', 'OK', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eq["device_id"],
                    eq["name"],
                    eq["device_type"],
                    eq["location"],
                    eq["description"],
                    eq["is_simulated"],
                    eq["is_enabled"],
                    eq["has_current_sensor"],
                    eq["temp_normal_min"],
                    eq["temp_normal_max"],
                    eq["temp_warning_threshold"],
                    eq["temp_critical_threshold"],
                    eq["vib_normal_min"],
                    eq["vib_normal_max"],
                    eq["vib_warning_threshold"],
                    eq["vib_critical_threshold"],
                    eq["current_normal_min"],
                    eq["current_normal_max"],
                    eq["current_warning_threshold"],
                    eq["current_critical_threshold"],
                    eq["persistence_window_count"],
                    now_iso,
                    now_iso,
                ),
            )
            db.execute(
                """
                INSERT INTO maintenance_notes (device_id, author_username, author_role, note_type, content, created_at)
                VALUES (?, 'admin', 'admin', 'CALIBRATION', ?, ?)
                """,
                (
                    eq["device_id"],
                    f"Initial baseline profile configured for {eq['name']} (simulated test rig). Normal vibration range {eq['vib_normal_min']}–{eq['vib_normal_max']} mm/s RMS.",
                    now_iso,
                ),
            )

    # 4. Seed initial genesis event & baseline telemetry if no readings exist yet
    reading_count_row = db.fetchone("SELECT COUNT(*) AS cnt FROM sensor_readings")
    reading_count = int(reading_count_row["cnt"]) if reading_count_row else 0

    if reading_count == 0:
        set_sync_connectivity_state(db, online=True, simulate_transient_failure=False, actor_username="system_seed")
        record_event_with_integrity(
            db=db,
            device_id="PUMP-01",
            metric="system",
            event_category="INTEGRITY",
            event_type="GENESIS_CHAIN_INITIALIZED",
            severity="INFO",
            rule_id="RULE_SYS_GENESIS",
            summary="RESILIX local append-only SHA-256 event chain initialized at genesis",
            explanation="Initialized local SQLite store-and-forward ledger and verified genesis hash anchor.",
            recommended_action="No action required; normal baseline monitoring active.",
            event_source="SYSTEM_SEED",
            enqueue_for_sync=True,
        )

        base_dt = datetime.now(timezone.utc) - timedelta(minutes=14)
        for step_i in range(1, 9):
            step_ts = (base_dt + timedelta(minutes=step_i * 1.5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            for idx, eq in enumerate(DEMO_EQUIPMENT):
                t_mid = (eq["temp_normal_min"] + eq["temp_normal_max"]) / 2.0
                v_mid = (eq["vib_normal_min"] + eq["vib_normal_max"]) / 2.0
                c_mid = (eq["current_normal_min"] + eq["current_normal_max"]) / 2.0
                offset = ((step_i + idx) % 3 - 1) * 0.35
                v_offset = ((step_i + idx) % 3 - 1) * 0.12
                ingest_and_evaluate_telemetry(
                    db,
                    skip_stale_check=True,
                    payload={
                        "device_id": eq["device_id"],
                        "sequence_number": step_i,
                        "timestamp": step_ts,
                        "temperature": round(t_mid + offset, 2),
                        "vibration": round(v_mid + v_offset, 2),
                        "current_amps": round(c_mid + v_offset * 1.5, 2),
                        "simulation_mode": "SIMULATED",
                        "scenario_name": "A_NORMAL",
                        "is_synthetic_anomaly": False,
                    },
                )

        run_synchronization_batch(db, batch_limit=50)

    return {
        "status": "SEEDED" if force_reset or seeded_devices > 0 else "ALREADY_INITIALIZED",
        "timestamp": now_iso,
    }
