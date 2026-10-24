"""
RESILIX Database Schema & Entity Definitions
Defines all 13 persistent relational tables, indexes, foreign keys, and constraints:
1. users
2. user_sessions
3. equipment
4. sensor_readings
5. events (unified event history including AnomalyEvent, telemetry, sensor_health, integrity, sync, auth, operator_action)
6. alerts
7. event_integrity_records (append-only SHA-256 hash chain)
8. sync_queue_items
9. sync_acknowledgements (simulated remote sink & ack ledger)
10. audit_logs
11. maintenance_notes
12. application_settings
13. scenario_executions
"""
from typing import Optional
from app.database import db_session

DDL_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
        password_hash TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
        last_failed_login_at TEXT,
        last_login_at TEXT,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS user_sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE,
        csrf_token TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS equipment (
        device_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        device_type TEXT NOT NULL CHECK (device_type IN ('water_pump', 'motor', 'fan', 'compressor', 'sensor_rig')),
        location TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        is_simulated INTEGER NOT NULL DEFAULT 1,
        is_enabled INTEGER NOT NULL DEFAULT 1,
        operational_status TEXT NOT NULL DEFAULT 'HEALTHY' CHECK (operational_status IN ('HEALTHY', 'WARNING', 'CRITICAL', 'OFFLINE', 'DISABLED')),
        sensor_health_status TEXT NOT NULL DEFAULT 'OK' CHECK (sensor_health_status IN ('OK', 'MISSING_SENSOR', 'STALE_DATA', 'IMPLAUSIBLE_READING', 'INCONSISTENT_SIGNAL', 'RECOVERED')),
        has_current_sensor INTEGER NOT NULL DEFAULT 1,
        temp_normal_min REAL NOT NULL DEFAULT 35.0,
        temp_normal_max REAL NOT NULL DEFAULT 50.0,
        temp_warning_threshold REAL NOT NULL DEFAULT 58.0,
        temp_critical_threshold REAL NOT NULL DEFAULT 68.0,
        temp_physical_min REAL NOT NULL DEFAULT -10.0,
        temp_physical_max REAL NOT NULL DEFAULT 130.0,
        vib_normal_min REAL NOT NULL DEFAULT 1.0,
        vib_normal_max REAL NOT NULL DEFAULT 3.0,
        vib_warning_threshold REAL NOT NULL DEFAULT 4.5,
        vib_critical_threshold REAL NOT NULL DEFAULT 7.0,
        vib_physical_min REAL NOT NULL DEFAULT 0.0,
        vib_physical_max REAL NOT NULL DEFAULT 50.0,
        current_normal_min REAL NOT NULL DEFAULT 3.5,
        current_normal_max REAL NOT NULL DEFAULT 6.5,
        current_warning_threshold REAL NOT NULL DEFAULT 8.5,
        current_critical_threshold REAL NOT NULL DEFAULT 11.0,
        persistence_window_count INTEGER NOT NULL DEFAULT 2,
        last_sequence_number INTEGER NOT NULL DEFAULT 0,
        last_telemetry_at TEXT,
        latest_temperature REAL,
        latest_vibration REAL,
        latest_current REAL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS sensor_readings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL REFERENCES equipment(device_id),
        sequence_number INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        received_at TEXT NOT NULL,
        temperature REAL,
        vibration REAL,
        current_amps REAL,
        validation_state TEXT NOT NULL CHECK (validation_state IN ('ACCEPTED', 'SUSPECT', 'REJECTED')),
        validation_flags TEXT NOT NULL DEFAULT '[]',
        simulation_mode TEXT NOT NULL DEFAULT 'SIMULATED',
        scenario_name TEXT NOT NULL DEFAULT 'normal_operation',
        is_synthetic_anomaly INTEGER NOT NULL DEFAULT 0,
        raw_payload TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_readings_device_time ON sensor_readings(device_id, timestamp DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_readings_validation ON sensor_readings(validation_state, timestamp DESC);
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY,
        sequence_index INTEGER NOT NULL UNIQUE,
        device_id TEXT REFERENCES equipment(device_id),
        metric TEXT NOT NULL DEFAULT 'system',
        event_category TEXT NOT NULL CHECK (event_category IN ('ANOMALY', 'SENSOR_HEALTH', 'INTEGRITY', 'SYNCHRONIZATION', 'AUTHENTICATION', 'OPERATOR_ACTION', 'TELEMETRY_QUALITY')),
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
        timestamp TEXT NOT NULL,
        observed_value REAL,
        baseline_value REAL,
        threshold_value REAL,
        deviation_score REAL,
        persistence_count INTEGER NOT NULL DEFAULT 1,
        rule_id TEXT NOT NULL,
        summary TEXT NOT NULL,
        explanation TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        event_source TEXT NOT NULL DEFAULT 'SIMULATOR_BACKEND',
        acknowledged INTEGER NOT NULL DEFAULT 0,
        acknowledged_by TEXT,
        acknowledged_at TEXT,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_events_device_time ON events(device_id, timestamp DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_events_category_sev ON events(event_category, severity, timestamp DESC);
    """,
    """
    CREATE TABLE IF NOT EXISTS event_integrity_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id) ON DELETE CASCADE,
        chain_index INTEGER NOT NULL UNIQUE,
        canonical_payload TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        hash_algorithm TEXT NOT NULL DEFAULT 'SHA-256',
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_integrity_chain ON event_integrity_records(chain_index ASC);
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL REFERENCES events(event_id),
        device_id TEXT NOT NULL REFERENCES equipment(device_id),
        severity TEXT NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
        alert_type TEXT NOT NULL,
        metric TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        explanation TEXT NOT NULL,
        recommended_action TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        observed_value REAL,
        threshold_value REAL,
        lifecycle_state TEXT NOT NULL DEFAULT 'OPEN' CHECK (lifecycle_state IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
        occurrence_count INTEGER NOT NULL DEFAULT 1,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        acknowledged_by TEXT,
        acknowledged_at TEXT,
        resolved_by TEXT,
        resolved_at TEXT,
        resolution_note TEXT,
        is_false_alert INTEGER
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_alerts_state_sev ON alerts(lifecycle_state, severity, last_seen_at DESC);
    """,
    """
    CREATE TABLE IF NOT EXISTS sync_queue_items (
        queue_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id) ON DELETE CASCADE,
        device_id TEXT,
        idempotency_key TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        sync_state TEXT NOT NULL DEFAULT 'PENDING' CHECK (sync_state IN ('PENDING', 'SYNCING', 'SYNCED', 'FAILED')),
        attempt_count INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 5,
        next_retry_at TEXT,
        last_attempt_at TEXT,
        last_error TEXT,
        ack_id TEXT,
        created_at TEXT NOT NULL,
        synced_at TEXT
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_sync_queue_state ON sync_queue_items(sync_state, created_at ASC);
    """,
    """
    CREATE TABLE IF NOT EXISTS sync_acknowledgements (
        ack_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        event_id TEXT NOT NULL UNIQUE,
        device_id TEXT,
        event_hash TEXT NOT NULL,
        verified_integrity INTEGER NOT NULL DEFAULT 1,
        remote_sink_label TEXT NOT NULL DEFAULT 'SIMULATED_REMOTE_SINK_V1',
        received_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor_username TEXT NOT NULL,
        actor_role TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT,
        status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'DENIED', 'FAILED')),
        ip_address TEXT,
        details_json TEXT NOT NULL DEFAULT '{}'
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp DESC);
    """,
    """
    CREATE TABLE IF NOT EXISTS maintenance_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL REFERENCES equipment(device_id) ON DELETE CASCADE,
        author_username TEXT NOT NULL,
        author_role TEXT NOT NULL,
        note_type TEXT NOT NULL DEFAULT 'INSPECTION' CHECK (note_type IN ('INSPECTION', 'CALIBRATION', 'REPAIR', 'OBSERVATION')),
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS application_settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_by TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS scenario_executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scenario_code TEXT NOT NULL,
        scenario_name TEXT NOT NULL,
        device_id TEXT NOT NULL,
        expected_behavior TEXT NOT NULL,
        observed_outcome TEXT NOT NULL,
        passed INTEGER NOT NULL DEFAULT 1,
        warning_latency_ms REAL,
        readings_generated INTEGER NOT NULL DEFAULT 0,
        events_created INTEGER NOT NULL DEFAULT 0,
        executed_by TEXT NOT NULL,
        executed_at TEXT NOT NULL
    );
    """
]


def init_db_schema(db_path: Optional[str] = None) -> None:
    with db_session(db_path) as session:
        for stmt in DDL_STATEMENTS:
            session.execute(stmt)
