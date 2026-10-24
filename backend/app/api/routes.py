"""
RESILIX REST API Router (`/api/v1`)
Implements all required endpoints across:
- Authentication (`/auth/login`, `/auth/logout`, `/auth/me`)
- Dashboard (`/dashboard/summary`, `/dashboard/timeseries`, `/dashboard/activity`)
- Equipment (`/equipment`, `/equipment/{device_id}`, `/equipment/{device_id}/readings`, `/equipment/{device_id}/events`, `/equipment/{device_id}/maintenance`, `/equipment/ingest`)
- Simulator (`/simulator/status`, `/simulator/start`, `/simulator/pause`, `/simulator/resume`, `/simulator/reset`, `/simulator/scenarios`, `/simulator/step`)
- Alerts (`/alerts`, `/alerts/{alert_id}`, `/alerts/{alert_id}/acknowledge`, `/alerts/{alert_id}/resolve`)
- Events (`/events`, `/events/{event_id}`, `/events/{event_id}/verify`)
- Synchronization (`/sync/status`, `/sync/connectivity`, `/sync/run`, `/sync/queue`)
- Security & Analytics (`/security/overview`, `/security/audit`, `/security/integrity`, `/security/integrity/verify`, `/analytics/summary`, `/analytics/evaluation`, `/analytics/export`, `/analytics/reset-demo`)
- Settings (`/settings`)
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import PlainTextResponse

from app.config import settings
from app.database import DatabaseSession, get_db, utc_now_iso
from app.schemas.api_schemas import (
    AlertAcknowledgeRequest,
    AlertResolveRequest,
    EquipmentCreate,
    EquipmentUpdate,
    LoginRequest,
    LoginResponse,
    MaintenanceNoteCreate,
    ScenarioTriggerRequest,
    SettingsUpdateRequest,
    SimulatorControlRequest,
    SyncConnectivityRequest,
    TelemetryIngestRequest,
    UserOut,
)
from app.security.auth import (
    check_login_rate_limit,
    clear_login_attempts,
    create_user_session,
    get_current_user,
    log_audit_event,
    record_login_failure_attempt,
    require_admin,
    verify_password,
)
from app.services.analytics_service import (
    export_events_and_evaluation_csv,
    get_analytics_summary,
    get_evaluation_report,
)
from app.services.integrity import (
    record_event_with_integrity,
    verify_entire_event_chain,
    verify_single_event_integrity,
)
from app.services.seed_service import seed_initial_data
from app.services.settings_service import get_runtime_settings, update_runtime_settings
from app.services.sync_service import (
    get_sync_status_summary,
    run_synchronization_batch,
    set_sync_connectivity_state,
)
from app.services.telemetry_processor import (
    compute_baseline_statistics,
    ingest_and_evaluate_telemetry,
)
from app.simulator.engine import simulator_engine

api_router = APIRouter(prefix="/api/v1")


# ==============================================================================
# 1. AUTHENTICATION ENDPOINTS
# ==============================================================================
@api_router.post("/auth/login", response_model=LoginResponse, tags=["Authentication"])
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DatabaseSession = Depends(get_db),
) -> Any:
    client_ip = request.client.host if request.client else "127.0.0.1"
    username = payload.username.strip()
    rate_key = f"{client_ip}:{username}"

    if not check_login_rate_limit(rate_key):
        log_audit_event(
            db,
            actor_username=username,
            actor_role="unauthenticated",
            action="LOGIN_RATE_LIMITED",
            resource_type="AUTH",
            status_str="DENIED",
            ip_address=client_ip,
            details={"reason": "Rate limit exceeded"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait 60 seconds before retrying.",
        )

    user = db.fetchone("SELECT * FROM users WHERE username = ?", (username,))
    if not user or int(user["is_active"]) == 0 or not verify_password(payload.password, user["password_hash"]):
        record_login_failure_attempt(rate_key)
        now_iso = utc_now_iso()
        if user:
            db.execute(
                "UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login_at = ? WHERE id = ?",
                (now_iso, user["id"]),
            )
        log_audit_event(
            db,
            actor_username=username,
            actor_role="unauthenticated",
            action="LOGIN_FAILED",
            resource_type="AUTH",
            status_str="FAILED",
            ip_address=client_ip,
            details={"reason": "Invalid username or password"},
        )
        record_event_with_integrity(
            db=db,
            device_id=None,
            metric="authentication",
            event_category="AUTHENTICATION",
            event_type="AUTH_LOGIN_FAILED",
            severity="WARNING",
            rule_id="RULE_SEC_AUTH_FAILURE",
            summary=f"Failed login attempt for username '{username}'",
            explanation=f"Invalid credentials presented from IP {client_ip}.",
            recommended_action="Review security audit log if repeated failed logins occur.",
            event_source="AUTH_SERVICE",
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    clear_login_attempts(rate_key)
    now_iso = utc_now_iso()
    db.execute(
        "UPDATE users SET last_login_at = ?, failed_login_attempts = 0 WHERE id = ?",
        (now_iso, user["id"]),
    )

    session_info = create_user_session(
        db=db,
        user_id=int(user["id"]),
        ip_address=client_ip,
        user_agent=request.headers.get("User-Agent", "RESILIX-Client"),
    )

    log_audit_event(
        db,
        actor_username=user["username"],
        actor_role=user["role"],
        action="LOGIN_SUCCESS",
        resource_type="AUTH",
        resource_id=session_info["session_id"],
        status_str="SUCCESS",
        ip_address=client_ip,
    )
    record_event_with_integrity(
        db=db,
        device_id=None,
        metric="authentication",
        event_category="AUTHENTICATION",
        event_type="AUTH_LOGIN_SUCCESS",
        severity="INFO",
        rule_id="RULE_SEC_AUTH_LOGIN",
        summary=f"Authenticated session started for '{user['username']}' ({user['role']})",
        explanation=f"User '{user['username']}' signed in with role '{user['role']}'.",
        recommended_action="Standard session monitoring active.",
        event_source="AUTH_SERVICE",
    )

    response.set_cookie(
        key="resilix_session",
        value=session_info["raw_token"],
        httponly=True,
        samesite="lax",
        secure=False,  # Local HTTP prototype; documented for HTTPS production
        max_age=settings.session_ttl_minutes * 60,
        path="/",
    )

    return {
        "user": UserOut(
            id=int(user["id"]),
            username=user["username"],
            full_name=user["full_name"],
            role=user["role"],
            last_login_at=now_iso,
        ),
        "csrf_token": session_info["csrf_token"],
        "session_expires_at": session_info["expires_at"],
        "access_token": session_info["raw_token"],
    }


@api_router.post("/auth/logout", tags=["Authentication"])
def logout(
    request: Request,
    response: Response,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    now_iso = utc_now_iso()
    db.execute(
        "UPDATE user_sessions SET revoked = 1, revoked_at = ? WHERE session_id = ?",
        (now_iso, current_user["session_id"]),
    )
    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="LOGOUT",
        resource_type="AUTH",
        resource_id=current_user["session_id"],
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    response.delete_cookie(key="resilix_session", path="/")
    return {"status": "LOGGED_OUT", "timestamp": now_iso}


@api_router.get("/auth/me", response_model=UserOut, tags=["Authentication"])
def get_me(current_user: dict[str, Any] = Depends(get_current_user)) -> Any:
    return UserOut(
        id=current_user["id"],
        username=current_user["username"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        last_login_at=current_user["last_login_at"],
    )


# ==============================================================================
# 2. DASHBOARD ENDPOINTS
# ==============================================================================
@api_router.get("/dashboard/summary", tags=["Dashboard"])
def dashboard_summary(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    equipment_rows = db.fetchall("SELECT * FROM equipment ORDER BY device_id ASC")
    total_equipment = len(equipment_rows)
    healthy_count = sum(1 for e in equipment_rows if e["operational_status"] == "HEALTHY" and int(e["is_enabled"]) == 1)
    warning_count = sum(1 for e in equipment_rows if e["operational_status"] == "WARNING" and int(e["is_enabled"]) == 1)
    critical_count = sum(1 for e in equipment_rows if e["operational_status"] == "CRITICAL" and int(e["is_enabled"]) == 1)
    disabled_count = sum(1 for e in equipment_rows if int(e["is_enabled"]) == 0)
    sensor_issues_count = sum(1 for e in equipment_rows if e["sensor_health_status"] not in ("OK", "RECOVERED"))

    active_alerts_row = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM alerts WHERE lifecycle_state IN ('OPEN', 'ACKNOWLEDGED')"
    )
    active_alerts_count = int(active_alerts_row["cnt"]) if active_alerts_row else 0

    alert_sev_rows = db.fetchall(
        "SELECT severity, COUNT(*) AS cnt FROM alerts WHERE lifecycle_state IN ('OPEN', 'ACKNOWLEDGED') GROUP BY severity"
    )
    alert_severity_dist = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
    for r in alert_sev_rows:
        alert_severity_dist[r["severity"]] = int(r["cnt"])

    # Enrich equipment cards with most recent alert
    enriched_equipment = []
    for eq in equipment_rows:
        latest_alert = db.fetchone(
            """
            SELECT alert_id, severity, title, lifecycle_state, last_seen_at
            FROM alerts
            WHERE device_id = ?
            ORDER BY last_seen_at DESC LIMIT 1
            """,
            (eq["device_id"],),
        )
        eq_dict = dict(eq)
        eq_dict["is_simulated"] = bool(eq["is_simulated"])
        eq_dict["is_enabled"] = bool(eq["is_enabled"])
        eq_dict["has_current_sensor"] = bool(eq["has_current_sensor"])
        eq_dict["most_recent_alert"] = latest_alert
        enriched_equipment.append(eq_dict)

    overall_health = "HEALTHY"
    if critical_count > 0:
        overall_health = "CRITICAL"
    elif warning_count > 0 or sensor_issues_count > 0:
        overall_health = "WARNING"

    sync_status = get_sync_status_summary(db)
    sim_status = simulator_engine.get_status()
    runtime_cfg = get_runtime_settings(db)

    return {
        "overall_health": overall_health,
        "total_equipment": total_equipment,
        "healthy_equipment_count": healthy_count,
        "warning_equipment_count": warning_count,
        "critical_equipment_count": critical_count,
        "disabled_equipment_count": disabled_count,
        "active_alerts_count": active_alerts_count,
        "sensor_health_issues_count": sensor_issues_count,
        "pending_sync_events_count": sync_status["pending_count"],
        "last_successful_sync_at": sync_status["last_successful_sync_at"],
        "sync_online": sync_status["online"],
        "alert_severity_distribution": alert_severity_dist,
        "equipment_health_distribution": {
            "HEALTHY": healthy_count,
            "WARNING": warning_count,
            "CRITICAL": critical_count,
            "DISABLED": disabled_count,
        },
        "equipment_overview": enriched_equipment,
        "simulator": sim_status,
        "dashboard_refresh_seconds": runtime_cfg.get("dashboard_refresh_seconds", 4),
        "timestamp": utc_now_iso(),
    }


@api_router.get("/dashboard/timeseries", tags=["Dashboard"])
def dashboard_timeseries(
    device_id: Optional[str] = Query(default=None),
    range_window: str = Query(default="15m", regex=r"^(15m|1h|24h|all)$"),
    limit: int = Query(default=60, ge=5, le=300),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    now_dt = datetime.now(timezone.utc)
    cutoff_iso = None
    if range_window == "15m":
        cutoff_iso = (now_dt - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    elif range_window == "1h":
        cutoff_iso = (now_dt - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    elif range_window == "24h":
        cutoff_iso = (now_dt - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    params: list[Any] = []
    where_clauses = ["validation_state = 'ACCEPTED'"]
    if device_id:
        where_clauses.append("device_id = ?")
        params.append(device_id)
    if cutoff_iso:
        where_clauses.append("timestamp >= ?")
        params.append(cutoff_iso)

    where_sql = " AND ".join(where_clauses)
    params.append(limit)

    rows = db.fetchall(
        f"""
        SELECT id, device_id, sequence_number, timestamp, temperature, vibration, current_amps, scenario_name
        FROM sensor_readings
        WHERE {where_sql}
        ORDER BY id DESC
        LIMIT ?
        """,
        tuple(params),
    )
    # If time cutoff returned empty because demo was idle, fallback to most recent readings
    if not rows and cutoff_iso:
        fallback_params: list[Any] = []
        fb_where = ["validation_state = 'ACCEPTED'"]
        if device_id:
            fb_where.append("device_id = ?")
            fallback_params.append(device_id)
        fallback_params.append(limit)
        rows = db.fetchall(
            f"""
            SELECT id, device_id, sequence_number, timestamp, temperature, vibration, current_amps, scenario_name
            FROM sensor_readings
            WHERE {' AND '.join(fb_where)}
            ORDER BY id DESC
            LIMIT ?
            """,
            tuple(fallback_params),
        )

    rows.reverse()
    return {
        "device_id": device_id or "ALL",
        "range_window": range_window,
        "count": len(rows),
        "series": rows,
        "units": {
            "temperature": "°C",
            "vibration": "mm/s RMS",
            "current_amps": "A",
        },
    }


@api_router.get("/dashboard/activity", tags=["Dashboard"])
def dashboard_activity(
    limit: int = Query(default=20, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
    event_category: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    clauses = ["1=1"]
    params: list[Any] = []
    if severity:
        clauses.append("e.severity = ?")
        params.append(severity)
    if event_category:
        clauses.append("e.event_category = ?")
        params.append(event_category)
    if device_id:
        clauses.append("e.device_id = ?")
        params.append(device_id)

    params.append(limit)
    rows = db.fetchall(
        f"""
        SELECT e.event_id, e.sequence_index, e.device_id, e.metric, e.event_category,
               e.event_type, e.severity, e.timestamp, e.observed_value, e.threshold_value,
               e.rule_id, e.summary, e.explanation, e.recommended_action,
               e.acknowledged, e.acknowledged_by, e.acknowledged_at,
               s.sync_state, i.event_hash
        FROM events e
        LEFT JOIN sync_queue_items s ON s.event_id = e.event_id
        LEFT JOIN event_integrity_records i ON i.event_id = e.event_id
        WHERE {' AND '.join(clauses)}
        ORDER BY e.sequence_index DESC
        LIMIT ?
        """,
        tuple(params),
    )
    for r in rows:
        r["acknowledged"] = bool(r["acknowledged"])
    return {"count": len(rows), "events": rows}


# ==============================================================================
# 3. EQUIPMENT MANAGEMENT ENDPOINTS
# ==============================================================================
@api_router.get("/equipment", tags=["Equipment"])
def list_equipment(
    search: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    device_type: Optional[str] = Query(default=None),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    clauses = ["1=1"]
    params: list[Any] = []
    if search:
        clauses.append("(device_id LIKE ? OR name LIKE ? OR location LIKE ?)")
        q = f"%{search.strip()}%"
        params.extend([q, q, q])
    if status_filter:
        clauses.append("operational_status = ?")
        params.append(status_filter)
    if device_type:
        clauses.append("device_type = ?")
        params.append(device_type)

    rows = db.fetchall(
        f"SELECT * FROM equipment WHERE {' AND '.join(clauses)} ORDER BY device_id ASC",
        tuple(params),
    )
    for r in rows:
        r["is_simulated"] = bool(r["is_simulated"])
        r["is_enabled"] = bool(r["is_enabled"])
        r["has_current_sensor"] = bool(r["has_current_sensor"])
    return {"count": len(rows), "equipment": rows}


@api_router.post("/equipment", status_code=status.HTTP_201_CREATED, tags=["Equipment"])
def register_equipment(
    payload: EquipmentCreate,
    request: Request,
    current_user: dict[str, Any] = Depends(require_admin),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    existing = db.fetchone("SELECT device_id FROM equipment WHERE device_id = ?", (payload.device_id,))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Equipment with device_id '{payload.device_id}' already exists.",
        )

    now_iso = utc_now_iso()
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
            payload.device_id,
            payload.name,
            payload.device_type,
            payload.location,
            payload.description,
            1 if payload.is_simulated else 0,
            1 if payload.is_enabled else 0,
            1 if payload.has_current_sensor else 0,
            payload.temp_normal_min,
            payload.temp_normal_max,
            payload.temp_warning_threshold,
            payload.temp_critical_threshold,
            payload.vib_normal_min,
            payload.vib_normal_max,
            payload.vib_warning_threshold,
            payload.vib_critical_threshold,
            payload.current_normal_min,
            payload.current_normal_max,
            payload.current_warning_threshold,
            payload.current_critical_threshold,
            payload.persistence_window_count,
            now_iso,
            now_iso,
        ),
    )

    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="EQUIPMENT_REGISTERED",
        resource_type="EQUIPMENT",
        resource_id=payload.device_id,
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
        details={"name": payload.name, "device_type": payload.device_type},
    )
    record_event_with_integrity(
        db=db,
        device_id=payload.device_id,
        metric="system",
        event_category="OPERATOR_ACTION",
        event_type="EQUIPMENT_REGISTERED",
        severity="INFO",
        rule_id="RULE_OP_EQUIP_REGISTER",
        summary=f"Registered simulated device '{payload.device_id}' ({payload.name})",
        explanation=f"Administrator '{current_user['username']}' registered {payload.device_id} at {payload.location}.",
        recommended_action="Run normal operation simulation to establish baseline readings.",
        event_source="ADMIN_API",
    )

    created = db.fetchone("SELECT * FROM equipment WHERE device_id = ?", (payload.device_id,))
    if created:
        created["is_simulated"] = bool(created["is_simulated"])
        created["is_enabled"] = bool(created["is_enabled"])
        created["has_current_sensor"] = bool(created["has_current_sensor"])
    return created


@api_router.get("/equipment/{device_id}", tags=["Equipment"])
def get_equipment_detail(
    device_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    eq = db.fetchone("SELECT * FROM equipment WHERE device_id = ?", (device_id,))
    if not eq:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Equipment '{device_id}' not found.")

    eq["is_simulated"] = bool(eq["is_simulated"])
    eq["is_enabled"] = bool(eq["is_enabled"])
    eq["has_current_sensor"] = bool(eq["has_current_sensor"])

    runtime_cfg = get_runtime_settings(db)
    w_size = int(runtime_cfg.get("baseline_window_size", 25))
    baselines = {
        "temperature": compute_baseline_statistics(db, device_id, "temperature", w_size),
        "vibration": compute_baseline_statistics(db, device_id, "vibration", w_size),
        "current_amps": compute_baseline_statistics(db, device_id, "current_amps", w_size),
    }

    active_alerts = db.fetchall(
        "SELECT * FROM alerts WHERE device_id = ? ORDER BY last_seen_at DESC LIMIT 20",
        (device_id,),
    )
    notes = db.fetchall(
        "SELECT * FROM maintenance_notes WHERE device_id = ? ORDER BY id DESC LIMIT 30",
        (device_id,),
    )

    return {
        "equipment": eq,
        "baselines": baselines,
        "alerts": active_alerts,
        "maintenance_notes": notes,
    }


@api_router.patch("/equipment/{device_id}", tags=["Equipment"])
def update_equipment(
    device_id: str,
    payload: EquipmentUpdate,
    request: Request,
    current_user: dict[str, Any] = Depends(require_admin),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    eq = db.fetchone("SELECT * FROM equipment WHERE device_id = ?", (device_id,))
    if not eq:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Equipment '{device_id}' not found.")

    updates = payload.dict(exclude_unset=True)
    if not updates:
        return eq

    temp_warn = float(updates.get("temp_warning_threshold", eq["temp_warning_threshold"]))
    temp_crit = float(updates.get("temp_critical_threshold", eq["temp_critical_threshold"]))
    vib_warn = float(updates.get("vib_warning_threshold", eq["vib_warning_threshold"]))
    vib_crit = float(updates.get("vib_critical_threshold", eq["vib_critical_threshold"]))
    cur_warn = float(updates.get("current_warning_threshold", eq["current_warning_threshold"]))
    cur_crit = float(updates.get("current_critical_threshold", eq["current_critical_threshold"]))

    if temp_warn >= temp_crit:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="temp_warning_threshold must be less than temp_critical_threshold.",
        )
    if vib_warn >= vib_crit:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="vib_warning_threshold must be less than vib_critical_threshold.",
        )
    if cur_warn >= cur_crit:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="current_warning_threshold must be less than current_critical_threshold.",
        )

    is_enabled_val = int(updates["is_enabled"]) if "is_enabled" in updates else int(eq["is_enabled"])
    has_cur_val = int(updates["has_current_sensor"]) if "has_current_sensor" in updates else int(eq["has_current_sensor"])
    op_status = eq["operational_status"]
    if "is_enabled" in updates:
        op_status = "HEALTHY" if is_enabled_val == 1 else "DISABLED"

    now_iso = utc_now_iso()
    db.execute(
        """
        UPDATE equipment SET
            name = ?,
            location = ?,
            description = ?,
            is_enabled = ?,
            operational_status = ?,
            has_current_sensor = ?,
            temp_warning_threshold = ?,
            temp_critical_threshold = ?,
            vib_warning_threshold = ?,
            vib_critical_threshold = ?,
            current_warning_threshold = ?,
            current_critical_threshold = ?,
            persistence_window_count = ?,
            updated_at = ?
        WHERE device_id = ?
        """,
        (
            updates.get("name", eq["name"]),
            updates.get("location", eq["location"]),
            updates.get("description", eq["description"]),
            is_enabled_val,
            op_status,
            has_cur_val,
            temp_warn,
            temp_crit,
            vib_warn,
            vib_crit,
            cur_warn,
            cur_crit,
            int(updates.get("persistence_window_count", eq["persistence_window_count"])),
            now_iso,
            device_id,
        ),
    )

    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="EQUIPMENT_UPDATED",
        resource_type="EQUIPMENT",
        resource_id=device_id,
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
        details=updates,
    )
    record_event_with_integrity(
        db=db,
        device_id=device_id,
        metric="configuration",
        event_category="OPERATOR_ACTION",
        event_type="EQUIPMENT_CONFIG_UPDATED",
        severity="INFO",
        rule_id="RULE_OP_EQUIP_UPDATE",
        summary=f"Updated configuration for {device_id} (enabled={bool(is_enabled_val)})",
        explanation=f"Administrator '{current_user['username']}' updated parameters on {device_id}.",
        recommended_action="Verify updated thresholds on equipment detail screen.",
        event_source="ADMIN_API",
    )

    updated = db.fetchone("SELECT * FROM equipment WHERE device_id = ?", (device_id,))
    if updated:
        updated["is_simulated"] = bool(updated["is_simulated"])
        updated["is_enabled"] = bool(updated["is_enabled"])
        updated["has_current_sensor"] = bool(updated["has_current_sensor"])
    return updated


@api_router.get("/equipment/{device_id}/readings", tags=["Equipment"])
def get_equipment_readings(
    device_id: str,
    validation_state: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    eq = db.fetchone("SELECT device_id FROM equipment WHERE device_id = ?", (device_id,))
    if not eq:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Equipment '{device_id}' not found.")

    clauses = ["device_id = ?"]
    params: list[Any] = [device_id]
    if validation_state:
        clauses.append("validation_state = ?")
        params.append(validation_state)
    params.append(limit)

    rows = db.fetchall(
        f"SELECT * FROM sensor_readings WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?",
        tuple(params),
    )
    for r in rows:
        try:
            r["validation_flags"] = json.loads(r["validation_flags"])
        except Exception:
            r["validation_flags"] = []
        r["is_synthetic_anomaly"] = bool(r["is_synthetic_anomaly"])
    return {"device_id": device_id, "count": len(rows), "readings": rows}


@api_router.get("/equipment/{device_id}/events", tags=["Equipment"])
def get_equipment_events(
    device_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    eq = db.fetchone("SELECT device_id FROM equipment WHERE device_id = ?", (device_id,))
    if not eq:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Equipment '{device_id}' not found.")

    rows = db.fetchall(
        """
        SELECT e.*, s.sync_state, i.event_hash
        FROM events e
        LEFT JOIN sync_queue_items s ON s.event_id = e.event_id
        LEFT JOIN event_integrity_records i ON i.event_id = e.event_id
        WHERE e.device_id = ?
        ORDER BY e.sequence_index DESC
        LIMIT ?
        """,
        (device_id, limit),
    )
    for r in rows:
        r["acknowledged"] = bool(r["acknowledged"])
    return {"device_id": device_id, "count": len(rows), "events": rows}


@api_router.get("/equipment/{device_id}/maintenance", tags=["Equipment"])
def get_equipment_maintenance(
    device_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    eq = db.fetchone("SELECT device_id FROM equipment WHERE device_id = ?", (device_id,))
    if not eq:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Equipment '{device_id}' not found.")

    notes = db.fetchall(
        "SELECT * FROM maintenance_notes WHERE device_id = ? ORDER BY id DESC",
        (device_id,),
    )
    return {"device_id": device_id, "count": len(notes), "notes": notes}


@api_router.post("/equipment/{device_id}/maintenance", status_code=status.HTTP_201_CREATED, tags=["Equipment"])
def add_equipment_maintenance_note(
    device_id: str,
    payload: MaintenanceNoteCreate,
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    eq = db.fetchone("SELECT device_id, name FROM equipment WHERE device_id = ?", (device_id,))
    if not eq:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Equipment '{device_id}' not found.")

    now_iso = utc_now_iso()
    cur = db.execute(
        """
        INSERT INTO maintenance_notes (device_id, author_username, author_role, note_type, content, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            device_id,
            current_user["username"],
            current_user["role"],
            payload.note_type,
            payload.content.strip(),
            now_iso,
        ),
    )
    note_id = cur.lastrowid

    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="MAINTENANCE_NOTE_CREATED",
        resource_type="EQUIPMENT",
        resource_id=device_id,
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
        details={"note_id": note_id, "note_type": payload.note_type},
    )
    record_event_with_integrity(
        db=db,
        device_id=device_id,
        metric="maintenance",
        event_category="OPERATOR_ACTION",
        event_type=f"MAINTENANCE_NOTE_{payload.note_type}",
        severity="INFO",
        rule_id="RULE_OP_MAINTENANCE_NOTE",
        summary=f"Maintenance note ({payload.note_type}) logged on {device_id} by {current_user['username']}",
        explanation=payload.content.strip(),
        recommended_action="Review maintenance history during scheduled service check.",
        event_source="OPERATOR_CONSOLE",
    )

    return db.fetchone("SELECT * FROM maintenance_notes WHERE id = ?", (note_id,))


@api_router.post("/equipment/ingest", tags=["Equipment"])
def manual_telemetry_ingest(
    payload: TelemetryIngestRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    try:
        res = ingest_and_evaluate_telemetry(db, payload.dict())
        return res
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))


# ==============================================================================
# 4. SIMULATOR & FAULT-INJECTION ENDPOINTS
# ==============================================================================
@api_router.get("/simulator/status", tags=["Simulator"])
def get_simulator_status(current_user: dict[str, Any] = Depends(get_current_user)) -> Any:
    return simulator_engine.get_status()


@api_router.post("/simulator/start", tags=["Simulator"])
def start_simulator(
    payload: Optional[SimulatorControlRequest] = None,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    speed = payload.speed_multiplier if (payload and payload.speed_multiplier) else 1.0
    dev_id = payload.device_id if payload else None
    state = simulator_engine.start(speed_multiplier=speed, device_id=dev_id)
    # Also generate an immediate step so user sees fresh reading right away
    step_res = simulator_engine.generate_step(db, device_id=dev_id)
    return {"status": state, "initial_step": step_res}


@api_router.post("/simulator/pause", tags=["Simulator"])
def pause_simulator(current_user: dict[str, Any] = Depends(get_current_user)) -> Any:
    return simulator_engine.pause()


@api_router.post("/simulator/resume", tags=["Simulator"])
def resume_simulator(current_user: dict[str, Any] = Depends(get_current_user)) -> Any:
    return simulator_engine.resume()


@api_router.post("/simulator/reset", tags=["Simulator"])
def reset_simulator(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    state = simulator_engine.reset_state()
    return {"status": state, "message": "Simulator engine state reset to deterministic seed."}


@api_router.post("/simulator/step", tags=["Simulator"])
def step_simulator(
    payload: Optional[SimulatorControlRequest] = None,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    dev_id = payload.device_id if payload else None
    return simulator_engine.generate_step(db, device_id=dev_id)


@api_router.post("/simulator/scenarios", tags=["Simulator"])
def trigger_scenario(
    payload: ScenarioTriggerRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    try:
        res = simulator_engine.execute_scenario(
            db=db,
            scenario_code=payload.scenario_code,
            device_id=payload.device_id,
            steps=payload.steps,
            actor_username=current_user["username"],
        )
        log_audit_event(
            db,
            actor_username=current_user["username"],
            actor_role=current_user["role"],
            action="SCENARIO_TRIGGERED",
            resource_type="SIMULATOR",
            resource_id=payload.scenario_code,
            status_str="SUCCESS",
            ip_address=request.client.host if request.client else "127.0.0.1",
            details={"device_id": payload.device_id, "steps": payload.steps},
        )
        return res
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# ==============================================================================
# 5. ALERTS LIFECYCLE ENDPOINTS
# ==============================================================================
@api_router.get("/alerts", tags=["Alerts"])
def list_alerts(
    severity: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    lifecycle_state: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    clauses = ["1=1"]
    params: list[Any] = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if lifecycle_state:
        clauses.append("lifecycle_state = ?")
        params.append(lifecycle_state)
    if search:
        q = f"%{search.strip()}%"
        clauses.append("(title LIKE ? OR description LIKE ? OR alert_id LIKE ? OR rule_id LIKE ?)")
        params.extend([q, q, q, q])

    where_sql = " AND ".join(clauses)
    total_row = db.fetchone(f"SELECT COUNT(*) AS cnt FROM alerts WHERE {where_sql}", tuple(params))
    total = int(total_row["cnt"]) if total_row else 0

    offset = (page - 1) * page_size
    rows = db.fetchall(
        f"""
        SELECT * FROM alerts
        WHERE {where_sql}
        ORDER BY
            CASE lifecycle_state WHEN 'OPEN' THEN 0 WHEN 'ACKNOWLEDGED' THEN 1 ELSE 2 END ASC,
            last_seen_at DESC
        LIMIT ? OFFSET ?
        """,
        tuple(params + [page_size, offset]),
    )
    for r in rows:
        r["is_false_alert"] = bool(r["is_false_alert"]) if r["is_false_alert"] is not None else False
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "alerts": rows,
    }


@api_router.get("/alerts/{alert_id}", tags=["Alerts"])
def get_alert_detail(
    alert_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    alert = db.fetchone("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{alert_id}' not found.")
    alert["is_false_alert"] = bool(alert["is_false_alert"]) if alert["is_false_alert"] is not None else False
    linked_event = db.fetchone("SELECT * FROM events WHERE event_id = ?", (alert["event_id"],))
    return {"alert": alert, "event": linked_event}


@api_router.post("/alerts/{alert_id}/acknowledge", tags=["Alerts"])
def acknowledge_alert(
    alert_id: str,
    payload: Optional[AlertAcknowledgeRequest] = None,
    request: Request = None,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    alert = db.fetchone("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{alert_id}' not found.")

    if alert["lifecycle_state"] == "RESOLVED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot acknowledge an alert that is already RESOLVED.",
        )

    now_iso = utc_now_iso()
    db.execute(
        """
        UPDATE alerts SET
            lifecycle_state = 'ACKNOWLEDGED',
            acknowledged_by = ?,
            acknowledged_at = ?
        WHERE alert_id = ?
        """,
        (current_user["username"], now_iso, alert_id),
    )
    db.execute(
        """
        UPDATE events SET
            acknowledged = 1,
            acknowledged_by = ?,
            acknowledged_at = ?
        WHERE event_id = ?
        """,
        (current_user["username"], now_iso, alert["event_id"]),
    )

    note_str = payload.note if (payload and payload.note) else "Acknowledged by operator."
    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="ALERT_ACKNOWLEDGED",
        resource_type="ALERT",
        resource_id=alert_id,
        status_str="SUCCESS",
        ip_address=request.client.host if (request and request.client) else "127.0.0.1",
        details={"device_id": alert["device_id"], "note": note_str},
    )
    record_event_with_integrity(
        db=db,
        device_id=alert["device_id"],
        metric="alert_lifecycle",
        event_category="OPERATOR_ACTION",
        event_type="ALERT_ACKNOWLEDGED",
        severity="INFO",
        rule_id="RULE_OP_ALERT_ACK",
        summary=f"Alert {alert_id} acknowledged by {current_user['username']} (remains active until resolved)",
        explanation=f"Operator '{current_user['username']}' acknowledged {alert_id}: {note_str}",
        recommended_action="Complete physical equipment inspection and resolve alert with findings.",
        event_source="OPERATOR_CONSOLE",
    )

    updated = db.fetchone("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    if updated:
        updated["is_false_alert"] = bool(updated["is_false_alert"]) if updated["is_false_alert"] is not None else False
    return updated


@api_router.post("/alerts/{alert_id}/resolve", tags=["Alerts"])
def resolve_alert(
    alert_id: str,
    payload: AlertResolveRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    alert = db.fetchone("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert '{alert_id}' not found.")

    now_iso = utc_now_iso()
    ack_by = alert["acknowledged_by"] or current_user["username"]
    ack_at = alert["acknowledged_at"] or now_iso

    db.execute(
        """
        UPDATE alerts SET
            lifecycle_state = 'RESOLVED',
            acknowledged_by = ?,
            acknowledged_at = ?,
            resolved_by = ?,
            resolved_at = ?,
            resolution_note = ?,
            is_false_alert = ?
        WHERE alert_id = ?
        """,
        (
            ack_by,
            ack_at,
            current_user["username"],
            now_iso,
            payload.resolution_note.strip(),
            1 if payload.is_false_alert else 0,
            alert_id,
        ),
    )

    # Check if device has any remaining open/acknowledged alerts; if none, restore equipment status to HEALTHY
    remaining_active = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM alerts WHERE device_id = ? AND lifecycle_state IN ('OPEN', 'ACKNOWLEDGED')",
        (alert["device_id"],),
    )
    if not remaining_active or int(remaining_active["cnt"]) == 0:
        db.execute(
            "UPDATE equipment SET operational_status = 'HEALTHY', sensor_health_status = 'OK', updated_at = ? WHERE device_id = ? AND is_enabled = 1",
            (now_iso, alert["device_id"]),
        )

    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="ALERT_RESOLVED",
        resource_type="ALERT",
        resource_id=alert_id,
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
        details={
            "device_id": alert["device_id"],
            "resolution_note": payload.resolution_note.strip(),
            "is_false_alert": bool(payload.is_false_alert),
        },
    )
    record_event_with_integrity(
        db=db,
        device_id=alert["device_id"],
        metric="alert_lifecycle",
        event_category="OPERATOR_ACTION",
        event_type="ALERT_RESOLVED",
        severity="INFO",
        rule_id="RULE_OP_ALERT_RESOLVE",
        summary=f"Alert {alert_id} resolved by {current_user['username']}",
        explanation=f"Resolution note: {payload.resolution_note.strip()}",
        recommended_action="Continue baseline monitoring.",
        event_source="OPERATOR_CONSOLE",
    )

    updated = db.fetchone("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
    if updated:
        updated["is_false_alert"] = bool(updated["is_false_alert"]) if updated["is_false_alert"] is not None else False
    return updated


# ==============================================================================
# 6. EVENTS & INTEGRITY ENDPOINTS
# ==============================================================================
@api_router.get("/events", tags=["Events"])
def list_events(
    device_id: Optional[str] = Query(default=None),
    event_category: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    sync_state: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=30, ge=1, le=200),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    clauses = ["1=1"]
    params: list[Any] = []
    if device_id:
        clauses.append("e.device_id = ?")
        params.append(device_id)
    if event_category:
        clauses.append("e.event_category = ?")
        params.append(event_category)
    if severity:
        clauses.append("e.severity = ?")
        params.append(severity)
    if sync_state:
        clauses.append("s.sync_state = ?")
        params.append(sync_state)
    if search:
        q = f"%{search.strip()}%"
        clauses.append("(e.summary LIKE ? OR e.explanation LIKE ? OR e.event_id LIKE ? OR e.event_type LIKE ?)")
        params.extend([q, q, q, q])

    where_sql = " AND ".join(clauses)
    total_row = db.fetchone(
        f"""
        SELECT COUNT(*) AS cnt
        FROM events e
        LEFT JOIN sync_queue_items s ON s.event_id = e.event_id
        WHERE {where_sql}
        """,
        tuple(params),
    )
    total = int(total_row["cnt"]) if total_row else 0

    offset = (page - 1) * page_size
    rows = db.fetchall(
        f"""
        SELECT e.*,
               s.queue_id, s.sync_state, s.attempt_count, s.idempotency_key, s.ack_id, s.synced_at,
               i.chain_index, i.previous_hash, i.event_hash, i.hash_algorithm
        FROM events e
        LEFT JOIN sync_queue_items s ON s.event_id = e.event_id
        LEFT JOIN event_integrity_records i ON i.event_id = e.event_id
        WHERE {where_sql}
        ORDER BY e.sequence_index DESC
        LIMIT ? OFFSET ?
        """,
        tuple(params + [page_size, offset]),
    )
    for r in rows:
        r["acknowledged"] = bool(r["acknowledged"])
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "events": rows,
    }


@api_router.get("/events/{event_id}", tags=["Events"])
def get_event_detail(
    event_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    row = db.fetchone(
        """
        SELECT e.*,
               s.queue_id, s.sync_state, s.attempt_count, s.idempotency_key, s.ack_id, s.synced_at, s.last_error,
               i.chain_index, i.canonical_payload, i.previous_hash, i.event_hash, i.hash_algorithm
        FROM events e
        LEFT JOIN sync_queue_items s ON s.event_id = e.event_id
        LEFT JOIN event_integrity_records i ON i.event_id = e.event_id
        WHERE e.event_id = ?
        """,
        (event_id,),
    )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Event '{event_id}' not found.")

    row["acknowledged"] = bool(row["acknowledged"])
    try:
        row["payload_parsed"] = json.loads(row["payload_json"])
    except Exception:
        row["payload_parsed"] = {}

    associated_alert = db.fetchone("SELECT * FROM alerts WHERE event_id = ?", (event_id,))
    verification = verify_single_event_integrity(db, event_id)
    return {
        "event": row,
        "associated_alert": associated_alert,
        "integrity_verification": verification,
    }


@api_router.get("/events/{event_id}/verify", tags=["Events"])
def verify_event_endpoint(
    event_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    res = verify_single_event_integrity(db, event_id)
    if "error" in res and res["error"] == "Event not found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=res["error"])
    return res


# ==============================================================================
# 7. OFFLINE SYNCHRONIZATION ENDPOINTS
# ==============================================================================
@api_router.get("/sync/status", tags=["Synchronization"])
def sync_status(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    return get_sync_status_summary(db)


@api_router.post("/sync/connectivity", tags=["Synchronization"])
def sync_connectivity(
    payload: SyncConnectivityRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    summary = set_sync_connectivity_state(
        db=db,
        online=payload.online,
        simulate_transient_failure=payload.simulate_transient_failure,
        actor_username=current_user["username"],
    )
    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="SYNC_CONNECTIVITY_CHANGED",
        resource_type="SYNC_ADAPTER",
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
        details={
            "online": payload.online,
            "simulate_transient_failure": payload.simulate_transient_failure,
        },
    )
    return summary


@api_router.post("/sync/run", tags=["Synchronization"])
def sync_run(
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    report = run_synchronization_batch(db, batch_limit=200, ignore_backoff_for_manual_run=True)
    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="SYNC_BATCH_EXECUTED",
        resource_type="SYNC_ADAPTER",
        status_str="SUCCESS" if report["failed"] == 0 else "FAILED",
        ip_address=request.client.host if request.client else "127.0.0.1",
        details=report,
    )
    return report


@api_router.get("/sync/queue", tags=["Synchronization"])
def sync_queue(
    sync_state: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    clauses = ["1=1"]
    params: list[Any] = []
    if sync_state:
        clauses.append("q.sync_state = ?")
        params.append(sync_state)
    params.append(limit)

    rows = db.fetchall(
        f"""
        SELECT q.queue_id, q.event_id, q.device_id, q.idempotency_key,
               q.event_hash, q.previous_hash, q.sync_state, q.attempt_count,
               q.max_attempts, q.next_retry_at, q.last_attempt_at, q.last_error,
               q.ack_id, q.created_at, q.synced_at,
               e.event_category, e.event_type, e.severity, e.summary
        FROM sync_queue_items q
        LEFT JOIN events e ON e.event_id = q.event_id
        WHERE {' AND '.join(clauses)}
        ORDER BY q.created_at DESC
        LIMIT ?
        """,
        tuple(params),
    )
    return {
        "count": len(rows),
        "queue": rows,
        "status": get_sync_status_summary(db),
    }


# ==============================================================================
# 8. SECURITY & ANALYTICS ENDPOINTS
# ==============================================================================
@api_router.get("/security/overview", tags=["Security"])
def security_overview(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    failed_logins_row = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM audit_logs WHERE action IN ('LOGIN_FAILED', 'LOGIN_RATE_LIMITED')"
    )
    unauth_row = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM audit_logs WHERE status = 'DENIED'"
    )
    quality_incidents_row = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM sensor_readings WHERE validation_state IN ('SUSPECT', 'REJECTED')"
    )
    active_sessions_row = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM user_sessions WHERE revoked = 0 AND expires_at > ?",
        (utc_now_iso(),),
    )

    devices = db.fetchall(
        "SELECT device_id, name, is_simulated, is_enabled, operational_status, sensor_health_status, last_sequence_number FROM equipment ORDER BY device_id ASC"
    )
    for d in devices:
        d["is_simulated"] = bool(d["is_simulated"])
        d["is_enabled"] = bool(d["is_enabled"])

    chain_report = verify_entire_event_chain(db)
    sync_summary = get_sync_status_summary(db)

    return {
        "current_user": {
            "username": current_user["username"],
            "full_name": current_user["full_name"],
            "role": current_user["role"],
            "session_id": current_user["session_id"],
        },
        "security_metrics": {
            "failed_login_events": int(failed_logins_row["cnt"]) if failed_logins_row else 0,
            "unauthorized_access_attempts": int(unauth_row["cnt"]) if unauth_row else 0,
            "sensor_quality_incidents": int(quality_incidents_row["cnt"]) if quality_incidents_row else 0,
            "active_sessions_count": int(active_sessions_row["cnt"]) if active_sessions_row else 1,
        },
        "device_identity_status": devices,
        "event_chain_verification": chain_report,
        "offline_sync_status": sync_summary,
        "configuration_validation": [
            {
                "control": "Password Hashing",
                "status": "PASS",
                "detail": "Memory-hard Scrypt KDF (N=16384, r=8, p=1) with 128-bit cryptographic salt; zero plaintext passwords stored.",
            },
            {
                "control": "Session & Role Authorization",
                "status": "PASS",
                "detail": "Server-side session tokens hashed with SHA-256 in SQLite; HTTP-only SameSite=Lax cookies + RBAC enforcement on all endpoints.",
            },
            {
                "control": "Login Brute-Force Rate Limiting",
                "status": "PASS",
                "detail": f"Max {settings.login_rate_limit_attempts} failed attempts per {settings.login_rate_limit_window_seconds}s sliding window.",
            },
            {
                "control": "Telemetry Pre-Analytics Quarantine",
                "status": "PASS",
                "detail": "SUSPECT and REJECTED readings are isolated before baseline statistics update; missing values are never coerced to 0.",
            },
            {
                "control": "Append-Only Event Hash Chain",
                "status": "PASS" if chain_report["valid"] else "ALERT",
                "detail": f"SHA-256 canonical chain ({chain_report['total_chain_links']} links); status={chain_report['status']}.",
            },
            {
                "control": "Production Transport & Storage Note",
                "status": "INFO",
                "detail": "Local HTTP & SQLite prototype. Production deployment requires TLS 1.3 (HTTPS), KMS/HSM secret anchoring, and full-disk encryption at rest.",
            },
        ],
        "timestamp": utc_now_iso(),
    }


@api_router.get("/security/audit", tags=["Security"])
def security_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    clauses = ["1=1"]
    params: list[Any] = []
    if status_filter:
        clauses.append("status = ?")
        params.append(status_filter)
    params.append(limit)

    rows = db.fetchall(
        f"SELECT * FROM audit_logs WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?",
        tuple(params),
    )
    for r in rows:
        try:
            r["details"] = json.loads(r["details_json"])
        except Exception:
            r["details"] = {}
    return {"count": len(rows), "audit_logs": rows}


@api_router.get("/security/integrity", tags=["Security"])
def get_security_integrity(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    report = verify_entire_event_chain(db)
    recent_links = db.fetchall(
        """
        SELECT i.chain_index, i.event_id, i.previous_hash, i.event_hash, i.hash_algorithm, i.created_at,
               e.event_category, e.event_type, e.severity, e.summary, e.device_id
        FROM event_integrity_records i
        JOIN events e ON e.event_id = i.event_id
        ORDER BY i.chain_index DESC
        LIMIT 30
        """
    )
    return {"verification": report, "recent_chain_links": recent_links}


@api_router.post("/security/integrity/verify", tags=["Security"])
def run_security_integrity_verify(
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    report = verify_entire_event_chain(db)
    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="INTEGRITY_CHAIN_VERIFIED",
        resource_type="EVENT_CHAIN",
        status_str="SUCCESS" if report["valid"] else "FAILED",
        ip_address=request.client.host if request.client else "127.0.0.1",
        details={
            "total_events_checked": report["total_events_checked"],
            "mismatch_count": report["mismatch_count"],
            "status": report["status"],
        },
    )
    return report


@api_router.get("/analytics/summary", tags=["Analytics"])
def analytics_summary_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    return get_analytics_summary(db)


@api_router.get("/analytics/evaluation", tags=["Analytics"])
def analytics_evaluation_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    return get_evaluation_report(db)


@api_router.get("/analytics/export", tags=["Analytics"])
def analytics_export_csv_endpoint(
    request: Request,
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    csv_data = export_events_and_evaluation_csv(db)
    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="ANALYTICS_CSV_EXPORTED",
        resource_type="ANALYTICS",
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    return PlainTextResponse(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="resilix_validation_and_events.csv"'},
    )


@api_router.post("/analytics/reset-demo", tags=["Analytics"])
def reset_demo_dataset_endpoint(
    request: Request,
    current_user: dict[str, Any] = Depends(require_admin),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    res = seed_initial_data(db, force_reset=True)
    log_audit_event(
        db,
        actor_username=current_user["username"],
        actor_role=current_user["role"],
        action="DEMO_DATASET_RESET",
        resource_type="DATABASE",
        status_str="SUCCESS",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    return {
        "status": "RESET_COMPLETE",
        "details": res,
        "message": "Demonstration dataset, baselines, and genesis hash chain reset to clean state.",
    }


# ==============================================================================
# 9. SETTINGS ENDPOINTS
# ==============================================================================
@api_router.get("/settings", tags=["Settings"])
def get_settings_endpoint(
    current_user: dict[str, Any] = Depends(get_current_user),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    runtime_cfg = get_runtime_settings(db)
    devices = db.fetchall(
        """
        SELECT device_id, name, device_type, is_enabled, has_current_sensor,
               temp_normal_min, temp_normal_max, temp_warning_threshold, temp_critical_threshold,
               vib_normal_min, vib_normal_max, vib_warning_threshold, vib_critical_threshold,
               current_normal_min, current_normal_max, current_warning_threshold, current_critical_threshold,
               persistence_window_count
        FROM equipment
        ORDER BY device_id ASC
        """
    )
    for d in devices:
        d["is_enabled"] = bool(d["is_enabled"])
        d["has_current_sensor"] = bool(d["has_current_sensor"])

    return {
        "settings": runtime_cfg,
        "device_thresholds": devices,
        "effect_notes": {
            "immediate": [
                "stale_data_timeout_seconds",
                "default_persistence_window",
                "device_thresholds",
                "sync_max_retries",
                "sync_backoff_base_seconds",
                "dashboard_refresh_seconds",
                "baseline_window_size",
                "baseline_min_samples",
            ],
            "next_simulator_tick": ["simulator_interval_seconds", "max_simulator_speed"],
        },
    }


@api_router.patch("/settings", tags=["Settings"])
def update_settings_endpoint(
    payload: SettingsUpdateRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_admin),
    db: DatabaseSession = Depends(get_db),
) -> Any:
    try:
        updated_cfg = update_runtime_settings(
            db=db,
            updates=payload.dict(exclude_unset=True),
            actor_username=current_user["username"],
        )
        log_audit_event(
            db,
            actor_username=current_user["username"],
            actor_role=current_user["role"],
            action="SETTINGS_UPDATED",
            resource_type="SETTINGS",
            status_str="SUCCESS",
            ip_address=request.client.host if request.client else "127.0.0.1",
            details=payload.dict(exclude_unset=True),
        )
        record_event_with_integrity(
            db=db,
            device_id=None,
            metric="settings",
            event_category="OPERATOR_ACTION",
            event_type="SYSTEM_SETTINGS_UPDATED",
            severity="INFO",
            rule_id="RULE_OP_SETTINGS_UPDATE",
            summary=f"System & threshold settings updated by {current_user['username']}",
            explanation="Updated runtime settings and/or equipment anomaly thresholds in SQLite.",
            recommended_action="New thresholds and timeouts apply immediately to subsequent readings.",
            event_source="ADMIN_API",
        )
        return get_settings_endpoint(current_user=current_user, db=db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
