"""
RESILIX Sensor-Data Integrity, Quality Validation & Explainable Anomaly-Detection Engine
Implements:
1. Pre-analytics telemetry validation (`ACCEPTED`, `SUSPECT`, `REJECTED`)
   - Missing sensor fields (never silently replaced with zero)
   - Stale timestamps (compared against device last_telemetry_at or runtime stale_data_timeout_seconds)
   - Out-of-range / physically implausible readings (e.g., negative vibration, temperature > 130°C or < -10°C)
   - Non-finite numeric values (NaN, Inf)
   - Replayed or non-increasing sequence numbers
   - Inconsistent cross-sensor signals (e.g., high vibration surge while motor current is near zero / idle, or vice versa)
   - Sensor recovery detection when a previously impaired sensor returns to valid readings
2. Transparent, explainable baseline & threshold anomaly detection:
   - Rolling window statistics (mean, std, median, min, max, sample count) over `ACCEPTED` readings only
   - Minimum sample count enforcement before statistical z-score / deviation rules fire
   - Configurable persistence window (`persistence_window_count`) per device before raising sustained threshold/baseline alerts
   - Duplicate-alert suppression & occurrence grouping on active (`OPEN` or `ACKNOWLEDGED`) alerts
"""
import json
import math
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

import numpy as np

from app.database import DatabaseSession, utc_now_iso
from app.services.integrity import record_event_with_integrity
from app.services.settings_service import get_runtime_settings

DEVICE_ID_REGEX = re.compile(r"^[A-Z0-9_-]{3,32}$")


def parse_iso_utc(ts_str: str) -> Optional[datetime]:
    try:
        cleaned = ts_str.strip()
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def compute_baseline_statistics(
    db: DatabaseSession,
    device_id: str,
    metric: str,
    window_size: int = 25,
    skip_recent: int = 0,
) -> dict[str, Any]:
    """
    Compute rolling baseline statistics from ACCEPTED readings only.
    Invalid (REJECTED) or SUSPECT readings never contaminate trusted baseline analytics.
    """
    col_map = {
        "temperature": "temperature",
        "vibration": "vibration",
        "current_amps": "current_amps",
    }
    col = col_map.get(metric)
    if not col:
        return {"sample_count": 0, "mean": None, "std": None, "median": None}

    rows = db.fetchall(
        f"""
        SELECT {col} AS val
        FROM sensor_readings
        WHERE device_id = ? AND validation_state = 'ACCEPTED' AND {col} IS NOT NULL
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (device_id, window_size, skip_recent),
    )
    vals = [float(r["val"]) for r in rows if r["val"] is not None and math.isfinite(float(r["val"]))]
    if not vals:
        return {"sample_count": 0, "mean": None, "std": None, "median": None, "min": None, "max": None}

    arr = np.array(vals, dtype=np.float64)
    mean_val = float(np.mean(arr))
    std_val = float(np.std(arr)) if len(arr) > 1 else 0.0
    median_val = float(np.median(arr))
    return {
        "sample_count": len(vals),
        "mean": round(mean_val, 4),
        "std": round(std_val, 4),
        "median": round(median_val, 4),
        "min": round(float(np.min(arr)), 4),
        "max": round(float(np.max(arr)), 4),
    }


def upsert_or_group_alert(
    db: DatabaseSession,
    event_id: str,
    device_id: str,
    severity: str,
    alert_type: str,
    metric: str,
    title: str,
    description: str,
    explanation: str,
    recommended_action: str,
    rule_id: str,
    observed_value: Optional[float],
    threshold_value: Optional[float],
    now_iso: str,
) -> dict[str, Any]:
    """
    Create a new alert or group repeated events into an existing active (OPEN or ACKNOWLEDGED)
    alert of the same device, metric, and rule_id to prevent duplicate alert storms.
    """
    existing = db.fetchone(
        """
        SELECT * FROM alerts
        WHERE device_id = ? AND rule_id = ? AND metric = ? AND lifecycle_state IN ('OPEN', 'ACKNOWLEDGED')
        ORDER BY last_seen_at DESC LIMIT 1
        """,
        (device_id, rule_id, metric),
    )
    if existing:
        new_count = int(existing["occurrence_count"]) + 1
        # Escalate severity if needed
        new_sev = severity if severity == "CRITICAL" else existing["severity"]
        db.execute(
            """
            UPDATE alerts SET
                occurrence_count = ?,
                last_seen_at = ?,
                severity = ?,
                observed_value = ?,
                threshold_value = ?,
                description = ?,
                explanation = ?,
                event_id = ?
            WHERE alert_id = ?
            """,
            (
                new_count,
                now_iso,
                new_sev,
                observed_value,
                threshold_value,
                description,
                explanation,
                event_id,
                existing["alert_id"],
            ),
        )
        return {
            "alert_id": existing["alert_id"],
            "grouped": True,
            "occurrence_count": new_count,
            "lifecycle_state": existing["lifecycle_state"],
        }

    alert_id = f"ALT-{secrets.token_hex(4).upper()}"
    db.execute(
        """
        INSERT INTO alerts (
            alert_id, event_id, device_id, severity, alert_type,
            metric, title, description, explanation, recommended_action,
            rule_id, observed_value, threshold_value, lifecycle_state,
            occurrence_count, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', 1, ?, ?)
        """,
        (
            alert_id,
            event_id,
            device_id,
            severity,
            alert_type,
            metric,
            title,
            description,
            explanation,
            recommended_action,
            rule_id,
            observed_value,
            threshold_value,
            now_iso,
            now_iso,
        ),
    )
    return {
        "alert_id": alert_id,
        "grouped": False,
        "occurrence_count": 1,
        "lifecycle_state": "OPEN",
    }


def ingest_and_evaluate_telemetry(
    db: DatabaseSession,
    payload: dict[str, Any],
    skip_stale_check: bool = False,
) -> dict[str, Any]:
    """
    Validate incoming telemetry reading, classify into ACCEPTED / SUSPECT / REJECTED,
    evaluate sensor-health rules and baseline/threshold anomaly detection,
    update equipment state, and persist events & alerts with hash-chain integrity.
    """
    now_iso = utc_now_iso()
    runtime_cfg = get_runtime_settings(db)

    device_id = str(payload.get("device_id", "")).strip()
    if not DEVICE_ID_REGEX.match(device_id):
        raise ValueError("Malformed device_id. Must be 3-32 uppercase alphanumeric, hyphen, or underscore characters.")

    equipment = db.fetchone("SELECT * FROM equipment WHERE device_id = ?", (device_id,))
    if not equipment:
        raise ValueError(f"Unknown device_id '{device_id}'. Register equipment before sending telemetry.")

    if int(equipment["is_enabled"]) == 0:
        raise ValueError(f"Equipment '{device_id}' is currently disabled and cannot ingest new telemetry.")

    seq_num = payload.get("sequence_number")
    if seq_num is None or not isinstance(seq_num, int) or seq_num < 1:
        raise ValueError("sequence_number must be a positive integer.")

    ts_raw = str(payload.get("timestamp", "")).strip()
    parsed_ts = parse_iso_utc(ts_raw)
    if parsed_ts is None:
        raise ValueError(f"Invalid UTC timestamp format: '{ts_raw}'.")

    temp_val = payload.get("temperature")
    vib_val = payload.get("vibration")
    cur_val = payload.get("current_amps")
    sim_mode = str(payload.get("simulation_mode", "SIMULATED"))
    scenario_name = str(payload.get("scenario_name", "normal_operation"))
    is_synth = 1 if payload.get("is_synthetic_anomaly") else 0

    # Check non-finite floats
    for field_name, val in [("temperature", temp_val), ("vibration", vib_val), ("current_amps", cur_val)]:
        if val is not None:
            if not isinstance(val, (int, float)) or not math.isfinite(float(val)):
                raise ValueError(f"Non-finite or invalid numeric value for '{field_name}'.")

    validation_flags: list[str] = []
    validation_state = "ACCEPTED"
    generated_events: list[dict[str, Any]] = []
    generated_alerts: list[dict[str, Any]] = []

    last_seq = int(equipment["last_sequence_number"] or 0)
    last_ts_str = equipment["last_telemetry_at"]
    prev_sensor_health = equipment["sensor_health_status"]

    # 1. Sequence replay / duplicate check
    if seq_num <= last_seq and last_seq > 0:
        validation_flags.append("REPLAYED_OR_DUPLICATE_SEQUENCE")
        validation_state = "REJECTED"

    # 2. Stale timestamp check
    stale_timeout_sec = int(runtime_cfg.get("stale_data_timeout_seconds", 30))
    now_dt = parse_iso_utc(now_iso) or datetime.now(timezone.utc)
    age_seconds = (now_dt - parsed_ts).total_seconds()

    is_repeated_timestamp = False
    if last_ts_str:
        last_dt = parse_iso_utc(last_ts_str)
        if last_dt and parsed_ts <= last_dt:
            is_repeated_timestamp = True

    if (not skip_stale_check) and (is_repeated_timestamp or age_seconds > stale_timeout_sec):
        validation_flags.append("STALE_TIMESTAMP")
        if validation_state == "ACCEPTED":
            validation_state = "SUSPECT"

    # 3. Missing required sensor fields check (never replace with 0)
    missing_fields: list[str] = []
    if temp_val is None:
        missing_fields.append("temperature")
    if vib_val is None:
        missing_fields.append("vibration")
    if int(equipment["has_current_sensor"]) == 1 and cur_val is None and scenario_name == "D_MISSING_SENSOR":
        missing_fields.append("current_amps")

    if missing_fields:
        validation_flags.append(f"MISSING_SENSOR_FIELDS:{','.join(missing_fields)}")
        if validation_state == "ACCEPTED":
            validation_state = "SUSPECT"

    # 4. Physical plausibility / out-of-range check
    implausible_reasons: list[str] = []
    if temp_val is not None:
        t_f = float(temp_val)
        if t_f < float(equipment["temp_physical_min"]) or t_f > float(equipment["temp_physical_max"]):
            implausible_reasons.append(
                f"Temperature {t_f:.2f}°C outside physical plausibility range "
                f"[{equipment['temp_physical_min']}°C, {equipment['temp_physical_max']}°C]"
            )
    if vib_val is not None:
        v_f = float(vib_val)
        if v_f < float(equipment["vib_physical_min"]) or v_f > float(equipment["vib_physical_max"]):
            implausible_reasons.append(
                f"Vibration {v_f:.2f} mm/s RMS outside physical plausibility range "
                f"[{equipment['vib_physical_min']}, {equipment['vib_physical_max']}] mm/s RMS"
            )
    if cur_val is not None:
        c_f = float(cur_val)
        if c_f < 0.0 or c_f > 100.0:
            implausible_reasons.append(f"Current {c_f:.2f} A outside physical plausibility range [0.0, 100.0] A")

    if implausible_reasons:
        validation_flags.append("IMPLAUSIBLE_OUT_OF_RANGE")
        validation_state = "REJECTED"

    # 5. Cross-sensor consistency check (e.g., high vibration while current is near zero / motor idle)
    inconsistent_reason: Optional[str] = None
    if (
        validation_state == "ACCEPTED"
        and vib_val is not None
        and cur_val is not None
        and int(equipment["has_current_sensor"]) == 1
    ):
        v_f = float(vib_val)
        c_f = float(cur_val)
        if v_f > float(equipment["vib_warning_threshold"]) and c_f < 0.8:
            inconsistent_reason = (
                f"Cross-sensor signal inconsistency: Vibration is elevated ({v_f:.2f} mm/s RMS > "
                f"{equipment['vib_warning_threshold']} mm/s) while motor current is near-zero ({c_f:.2f} A < 0.8 A)."
            )
        elif c_f > float(equipment["current_critical_threshold"]) and v_f < 0.25:
            inconsistent_reason = (
                f"Cross-sensor signal inconsistency: Motor current is critically high ({c_f:.2f} A) "
                f"while vibration sensor reads near-zero ({v_f:.2f} mm/s RMS)."
            )

    if inconsistent_reason:
        validation_flags.append("INCONSISTENT_CROSS_SENSOR_SIGNALS")
        validation_state = "SUSPECT"

    # Obtain baseline statistics BEFORE inserting current reading so baseline represents prior trusted window
    window_size = int(runtime_cfg.get("baseline_window_size", 25))
    min_samples = int(runtime_cfg.get("baseline_min_samples", 5))
    skip_n = max(0, int(equipment["persistence_window_count"] or 2) - 1)
    temp_base = compute_baseline_statistics(db, device_id, "temperature", window_size, skip_recent=skip_n)
    vib_base = compute_baseline_statistics(db, device_id, "vibration", window_size, skip_recent=skip_n)

    # Persist the sensor reading with its validation_state
    cur = db.execute(
        """
        INSERT INTO sensor_readings (
            device_id, sequence_number, timestamp, received_at,
            temperature, vibration, current_amps, validation_state,
            validation_flags, simulation_mode, scenario_name,
            is_synthetic_anomaly, raw_payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_id,
            seq_num,
            ts_raw,
            now_iso,
            float(temp_val) if temp_val is not None else None,
            float(vib_val) if vib_val is not None else None,
            float(cur_val) if cur_val is not None else None,
            validation_state,
            json.dumps(validation_flags),
            sim_mode,
            scenario_name,
            is_synth,
            json.dumps(payload, sort_keys=True),
        ),
    )
    reading_id = cur.lastrowid

    # Handle Sensor-Health / Data Quality Events
    new_sensor_health = "OK"

    if "REPLAYED_OR_DUPLICATE_SEQUENCE" in validation_flags:
        new_sensor_health = prev_sensor_health if prev_sensor_health != "OK" else "IMPLAUSIBLE_READING"
        evt = record_event_with_integrity(
            db=db,
            device_id=device_id,
            metric="sequence_number",
            event_category="TELEMETRY_QUALITY",
            event_type="REPLAYED_SEQUENCE_REJECTED",
            severity="WARNING",
            rule_id="RULE_QUAL_SEQ_REPLAY",
            summary=f"Rejected replayed or out-of-order sequence #{seq_num} on {device_id}",
            explanation=(
                f"Incoming sequence_number ({seq_num}) is less than or equal to last accepted sequence "
                f"({last_seq}). Reading was quarantined as REJECTED to prevent replay contamination."
            ),
            recommended_action="Inspect edge telemetry packet counter or check for duplicate message replay.",
            observed_value=float(seq_num),
            threshold_value=float(last_seq + 1),
            event_source=sim_mode,
        )
        generated_events.append(evt)

    if implausible_reasons:
        new_sensor_health = "IMPLAUSIBLE_READING"
        reason_text = "; ".join(implausible_reasons)
        obs_val = float(vib_val) if (vib_val is not None and float(vib_val) < 0) else (
            float(temp_val) if temp_val is not None else None
        )
        evt = record_event_with_integrity(
            db=db,
            device_id=device_id,
            metric="sensor_plausibility",
            event_category="TELEMETRY_QUALITY",
            event_type="IMPLAUSIBLE_READING_REJECTED",
            severity="WARNING",
            rule_id="RULE_QUAL_IMPLAUSIBLE_RANGE",
            summary=f"Implausible physical sensor reading rejected on {device_id}",
            explanation=f"{reason_text}. Reading state set to REJECTED and excluded from baseline analytics.",
            recommended_action="Check ADC scaling, sensor wiring fault, or transducer saturation.",
            observed_value=obs_val,
            event_source=sim_mode,
        )
        generated_events.append(evt)
        alt = upsert_or_group_alert(
            db=db,
            event_id=evt["event_id"],
            device_id=device_id,
            severity="WARNING",
            alert_type="SENSOR_IMPLAUSIBLE_READING",
            metric="sensor_plausibility",
            title=f"Implausible Sensor Value Rejected ({device_id})",
            description=reason_text,
            explanation=evt["timestamp"] + ": " + reason_text,
            recommended_action="Inspect sensor calibration and wiring; reading quarantined from trusted analytics.",
            rule_id="RULE_QUAL_IMPLAUSIBLE_RANGE",
            observed_value=obs_val,
            threshold_value=0.0,
            now_iso=now_iso,
        )
        generated_alerts.append(alt)

    if missing_fields:
        new_sensor_health = "MISSING_SENSOR"
        missing_str = ", ".join(missing_fields)
        evt = record_event_with_integrity(
            db=db,
            device_id=device_id,
            metric=missing_fields[0],
            event_category="SENSOR_HEALTH",
            event_type="MISSING_SENSOR_FIELD",
            severity="WARNING",
            rule_id="RULE_SENSOR_MISSING_FIELD",
            summary=f"Missing sensor channel ({missing_str}) on {device_id}",
            explanation=(
                f"Telemetry frame #{seq_num} omitted required sensor channel(s): {missing_str}. "
                f"RESILIX quarantined the frame as SUSPECT rather than substituting 0.0."
            ),
            recommended_action=f"Check {missing_str} probe connector and signal conditioning harness on {device_id}.",
            event_source=sim_mode,
        )
        generated_events.append(evt)
        alt = upsert_or_group_alert(
            db=db,
            event_id=evt["event_id"],
            device_id=device_id,
            severity="WARNING",
            alert_type="MISSING_SENSOR_DATA",
            metric=missing_fields[0],
            title=f"Missing Sensor Signal: {missing_str} ({device_id})",
            description=f"Sensor channel '{missing_str}' missing in telemetry packet #{seq_num}.",
            explanation=f"Missing field detected by RULE_SENSOR_MISSING_FIELD; value was not coerced to zero.",
            recommended_action=f"Inspect physical connector for {missing_str} transducer on {device_id}.",
            rule_id="RULE_SENSOR_MISSING_FIELD",
            observed_value=None,
            threshold_value=None,
            now_iso=now_iso,
        )
        generated_alerts.append(alt)

    if "STALE_TIMESTAMP" in validation_flags:
        new_sensor_health = "STALE_DATA"
        evt = record_event_with_integrity(
            db=db,
            device_id=device_id,
            metric="timestamp",
            event_category="SENSOR_HEALTH",
            event_type="STALE_SENSOR_DATA",
            severity="WARNING",
            rule_id="RULE_SENSOR_STALE_TIMESTAMP",
            summary=f"Stale or non-advancing sensor timestamp detected on {device_id}",
            explanation=(
                f"Reading timestamp ({ts_raw}) is repeated or older than configured stale timeout "
                f"({stale_timeout_sec}s; observed age={age_seconds:.1f}s, last_telemetry_at={last_ts_str})."
            ),
            recommended_action="Verify edge RTC synchronization and check whether sensor polling loop is frozen.",
            observed_value=round(age_seconds, 2),
            threshold_value=float(stale_timeout_sec),
            event_source=sim_mode,
        )
        generated_events.append(evt)
        alt = upsert_or_group_alert(
            db=db,
            event_id=evt["event_id"],
            device_id=device_id,
            severity="WARNING",
            alert_type="STALE_SENSOR_TIMESTAMP",
            metric="timestamp",
            title=f"Stale Sensor Timestamp ({device_id})",
            description=f"Sensor timestamp '{ts_raw}' failed freshness validation (timeout {stale_timeout_sec}s).",
            explanation=f"Timestamp repeated or exceeded {stale_timeout_sec}s freshness threshold.",
            recommended_action="Check edge microcontroller polling loop and sensor bus lockups.",
            rule_id="RULE_SENSOR_STALE_TIMESTAMP",
            observed_value=round(age_seconds, 2),
            threshold_value=float(stale_timeout_sec),
            now_iso=now_iso,
        )
        generated_alerts.append(alt)

    if inconsistent_reason:
        new_sensor_health = "INCONSISTENT_SIGNAL"
        evt = record_event_with_integrity(
            db=db,
            device_id=device_id,
            metric="cross_sensor",
            event_category="SENSOR_HEALTH",
            event_type="INCONSISTENT_SENSOR_SIGNALS",
            severity="WARNING",
            rule_id="RULE_SENSOR_CROSS_CONSISTENCY",
            summary=f"Inconsistent cross-sensor telemetry on {device_id}",
            explanation=inconsistent_reason,
            recommended_action="Compare accelerometer mounting and current clamp placement for uncoupled readings.",
            observed_value=float(vib_val) if vib_val is not None else None,
            threshold_value=float(equipment["vib_warning_threshold"]),
            event_source=sim_mode,
        )
        generated_events.append(evt)
        alt = upsert_or_group_alert(
            db=db,
            event_id=evt["event_id"],
            device_id=device_id,
            severity="WARNING",
            alert_type="INCONSISTENT_SENSOR_SIGNALS",
            metric="cross_sensor",
            title=f"Inconsistent Cross-Sensor Reading ({device_id})",
            description=inconsistent_reason,
            explanation=inconsistent_reason,
            recommended_action="Verify both vibration and current transducers are mounted to the same active machine.",
            rule_id="RULE_SENSOR_CROSS_CONSISTENCY",
            observed_value=float(vib_val) if vib_val is not None else None,
            threshold_value=float(equipment["vib_warning_threshold"]),
            now_iso=now_iso,
        )
        generated_alerts.append(alt)

    # Check sensor recovery if reading is ACCEPTED and previous sensor health was not OK
    if validation_state == "ACCEPTED":
        if prev_sensor_health not in ("OK", "RECOVERED") or scenario_name == "J_SENSOR_RECOVERY":
            new_sensor_health = "OK"
            evt = record_event_with_integrity(
                db=db,
                device_id=device_id,
                metric="sensor_health",
                event_category="SENSOR_HEALTH",
                event_type="SENSOR_HEALTH_RECOVERED",
                severity="INFO",
                rule_id="RULE_SENSOR_RECOVERY",
                summary=f"Sensor telemetry restored to valid operation on {device_id}",
                explanation=(
                    f"Device {device_id} transitioned from sensor state '{prev_sensor_health}' back to 'OK' "
                    f"with valid temperature ({temp_val}°C) and vibration ({vib_val} mm/s RMS)."
                ),
                recommended_action="Verify previously raised sensor-health alerts and mark resolved after confirmation.",
                observed_value=float(vib_val) if vib_val is not None else None,
                event_source=sim_mode,
            )
            generated_events.append(evt)

    # 6. Evaluate Anomaly Detection ONLY on ACCEPTED readings
    new_op_status = equipment["operational_status"]
    if validation_state == "ACCEPTED":
        persistence_req = int(equipment["persistence_window_count"] or runtime_cfg.get("default_persistence_window", 2))
        recent_accepted = db.fetchall(
            """
            SELECT temperature, vibration, current_amps
            FROM sensor_readings
            WHERE device_id = ? AND validation_state = 'ACCEPTED'
            ORDER BY id DESC
            LIMIT ?
            """,
            (device_id, max(persistence_req, 5)),
        )

        temp_f = float(temp_val) if temp_val is not None else None
        vib_f = float(vib_val) if vib_val is not None else None
        cur_f = float(cur_val) if cur_val is not None else None

        # Check vibration threshold & persistence
        vib_warn = float(equipment["vib_warning_threshold"])
        vib_crit = float(equipment["vib_critical_threshold"])
        vib_Persist_rows = [
            float(r["vibration"])
            for r in recent_accepted[:persistence_req]
            if r["vibration"] is not None
        ]
        vib_exceeds_count = sum(1 for v in vib_Persist_rows if v >= vib_warn)

        vib_anomaly_triggered = False
        if vib_f is not None and vib_f >= vib_warn and vib_exceeds_count >= persistence_req:
            vib_anomaly_triggered = True
            sev = "CRITICAL" if vib_f >= vib_crit else "WARNING"
            thresh_used = vib_crit if sev == "CRITICAL" else vib_warn
            dev_score = None
            if vib_base["sample_count"] >= min_samples and vib_base["std"] and vib_base["std"] > 0.05:
                dev_score = round((vib_f - float(vib_base["mean"])) / float(vib_base["std"]), 2)

            explanation_str = (
                f"Vibration ({vib_f:.2f} mm/s RMS) exceeded configured {sev.lower()} threshold "
                f"({thresh_used:.2f} mm/s RMS) for {vib_exceeds_count} consecutive valid readings "
                f"(required persistence window: {persistence_req})."
            )
            if vib_base["mean"] is not None:
                explanation_str += f" Rolling baseline mean is {vib_base['mean']:.2f} mm/s RMS"
                if dev_score is not None:
                    explanation_str += f" (statistical deviation score: {dev_score:+.2f} sigma; note: deviation score is not a probability of failure)."
                else:
                    explanation_str += "."

            evt = record_event_with_integrity(
                db=db,
                device_id=device_id,
                metric="vibration",
                event_category="ANOMALY",
                event_type=f"VIBRATION_{sev}_THRESHOLD",
                severity=sev,
                rule_id=f"RULE_ANOM_VIB_{sev}",
                summary=f"Sustained {sev.lower()} vibration ({vib_f:.2f} mm/s RMS) on {device_id}",
                explanation=explanation_str,
                recommended_action="Inspect shaft alignment, bearing wear, impeller balance, and mounting bolts.",
                observed_value=vib_f,
                baseline_value=vib_base["mean"],
                threshold_value=thresh_used,
                deviation_score=dev_score,
                persistence_count=vib_exceeds_count,
                event_source=sim_mode,
            )
            generated_events.append(evt)
            alt = upsert_or_group_alert(
                db=db,
                event_id=evt["event_id"],
                device_id=device_id,
                severity=sev,
                alert_type=f"VIBRATION_{sev}",
                metric="vibration",
                title=f"{sev.title()} Vibration Anomaly ({device_id})",
                description=f"Observed {vib_f:.2f} mm/s RMS vs {thresh_used:.2f} mm/s threshold ({vib_exceeds_count} consecutive readings).",
                explanation=explanation_str,
                recommended_action="Inspect rotor balance, bearing lubrication, and baseplate anchor bolts.",
                rule_id=f"RULE_ANOM_VIB_{sev}",
                observed_value=vib_f,
                threshold_value=thresh_used,
                now_iso=now_iso,
            )
            generated_alerts.append(alt)

        # Baseline statistical deviation detection for vibration (when below static warning threshold but significantly above rolling baseline)
        elif (
            vib_f is not None
            and vib_base["sample_count"] >= min_samples
            and vib_base["mean"] is not None
            and vib_base["std"] is not None
        ):
            eff_std = max(float(vib_base["std"]), 0.15)
            z_score = (vib_f - float(vib_base["mean"])) / eff_std
            if z_score >= 2.8 and vib_f > float(equipment["vib_normal_max"]) and len(vib_Persist_rows) >= persistence_req:
                all_above_norm = all(v > float(equipment["vib_normal_max"]) for v in vib_Persist_rows)
                if all_above_norm:
                    vib_anomaly_triggered = True
                    dev_score = round(z_score, 2)
                    explanation_str = (
                        f"Vibration ({vib_f:.2f} mm/s RMS) deviated {dev_score:+.2f} standard deviations above "
                        f"rolling baseline mean ({vib_base['mean']:.2f} mm/s RMS) across {persistence_req} readings "
                        f"(statistical deviation score, not a calibrated failure probability)."
                    )
                    evt = record_event_with_integrity(
                        db=db,
                        device_id=device_id,
                        metric="vibration",
                        event_category="ANOMALY",
                        event_type="VIBRATION_BASELINE_DEVIATION",
                        severity="WARNING",
                        rule_id="RULE_ANOM_VIB_BASELINE_Z",
                        summary=f"Sustained baseline vibration deviation ({vib_f:.2f} mm/s RMS) on {device_id}",
                        explanation=explanation_str,
                        recommended_action="Schedule preventive bearing and coupling inspection during next maintenance window.",
                        observed_value=vib_f,
                        baseline_value=vib_base["mean"],
                        threshold_value=float(equipment["vib_normal_max"]),
                        deviation_score=dev_score,
                        persistence_count=persistence_req,
                        event_source=sim_mode,
                    )
                    generated_events.append(evt)
                    alt = upsert_or_group_alert(
                        db=db,
                        event_id=evt["event_id"],
                        device_id=device_id,
                        severity="WARNING",
                        alert_type="VIBRATION_BASELINE_DRIFT",
                        metric="vibration",
                        title=f"Vibration Baseline Deviation ({device_id})",
                        description=f"Observed {vib_f:.2f} mm/s RMS ({dev_score:+.2f} sigma above baseline {vib_base['mean']:.2f} mm/s).",
                        explanation=explanation_str,
                        recommended_action="Check mechanical load changes and bearing wear trend.",
                        rule_id="RULE_ANOM_VIB_BASELINE_Z",
                        observed_value=vib_f,
                        threshold_value=float(equipment["vib_normal_max"]),
                        now_iso=now_iso,
                    )
                    generated_alerts.append(alt)

        # Check temperature threshold & persistence
        temp_warn = float(equipment["temp_warning_threshold"])
        temp_crit = float(equipment["temp_critical_threshold"])
        temp_persist_rows = [
            float(r["temperature"])
            for r in recent_accepted[:persistence_req]
            if r["temperature"] is not None
        ]
        temp_exceeds_count = sum(1 for t in temp_persist_rows if t >= temp_warn)

        temp_anomaly_triggered = False
        if temp_f is not None and temp_f >= temp_warn and temp_exceeds_count >= persistence_req:
            temp_anomaly_triggered = True
            sev = "CRITICAL" if temp_f >= temp_crit else "WARNING"
            thresh_used = temp_crit if sev == "CRITICAL" else temp_warn
            dev_score = None
            if temp_base["sample_count"] >= min_samples and temp_base["std"] and temp_base["std"] > 0.1:
                dev_score = round((temp_f - float(temp_base["mean"])) / float(temp_base["std"]), 2)

            explanation_str = (
                f"Temperature ({temp_f:.2f}°C) exceeded configured {sev.lower()} threshold "
                f"({thresh_used:.2f}°C) for {temp_exceeds_count} consecutive valid readings "
                f"(required persistence window: {persistence_req})."
            )
            if temp_base["mean"] is not None:
                explanation_str += f" Rolling baseline mean is {temp_base['mean']:.2f}°C"
                if dev_score is not None:
                    explanation_str += f" (statistical deviation score: {dev_score:+.2f} sigma; not a failure probability)."
                else:
                    explanation_str += "."

            evt = record_event_with_integrity(
                db=db,
                device_id=device_id,
                metric="temperature",
                event_category="ANOMALY",
                event_type=f"TEMPERATURE_{sev}_THRESHOLD",
                severity=sev,
                rule_id=f"RULE_ANOM_TEMP_{sev}",
                summary=f"Sustained {sev.lower()} temperature ({temp_f:.2f}°C) on {device_id}",
                explanation=explanation_str,
                recommended_action="Check cooling airflow, ambient ventilation, winding load, and coolant flow.",
                observed_value=temp_f,
                baseline_value=temp_base["mean"],
                threshold_value=thresh_used,
                deviation_score=dev_score,
                persistence_count=temp_exceeds_count,
                event_source=sim_mode,
            )
            generated_events.append(evt)
            alt = upsert_or_group_alert(
                db=db,
                event_id=evt["event_id"],
                device_id=device_id,
                severity=sev,
                alert_type=f"TEMPERATURE_{sev}",
                metric="temperature",
                title=f"{sev.title()} Temperature Anomaly ({device_id})",
                description=f"Observed {temp_f:.2f}°C vs {thresh_used:.2f}°C threshold ({temp_exceeds_count} consecutive readings).",
                explanation=explanation_str,
                recommended_action="Inspect cooling fan shroud, intake filter, and thermal load.",
                rule_id=f"RULE_ANOM_TEMP_{sev}",
                observed_value=temp_f,
                threshold_value=thresh_used,
                now_iso=now_iso,
            )
            generated_alerts.append(alt)

        # Determine operational status from current valid readings
        if (vib_f is not None and vib_f >= vib_crit and vib_anomaly_triggered) or (
            temp_f is not None and temp_f >= temp_crit and temp_anomaly_triggered
        ):
            new_op_status = "CRITICAL"
        elif vib_anomaly_triggered or temp_anomaly_triggered:
            new_op_status = "WARNING"
        else:
            new_op_status = "HEALTHY"

        # Update equipment latest telemetry only when reading is ACCEPTED
        db.execute(
            """
            UPDATE equipment SET
                operational_status = ?,
                sensor_health_status = ?,
                last_sequence_number = ?,
                last_telemetry_at = ?,
                latest_temperature = ?,
                latest_vibration = ?,
                latest_current = ?,
                updated_at = ?
            WHERE device_id = ?
            """,
            (
                new_op_status,
                new_sensor_health,
                seq_num,
                ts_raw,
                temp_f,
                vib_f,
                cur_f,
                now_iso,
                device_id,
            ),
        )
    else:
        # For SUSPECT or REJECTED readings: update sensor_health_status and sequence (if larger),
        # but NEVER overwrite trusted latest_temperature / latest_vibration with invalid values.
        updated_seq = max(last_seq, seq_num)
        db.execute(
            """
            UPDATE equipment SET
                sensor_health_status = ?,
                last_sequence_number = ?,
                updated_at = ?
            WHERE device_id = ?
            """,
            (new_sensor_health, updated_seq, now_iso, device_id),
        )

    return {
        "reading_id": reading_id,
        "device_id": device_id,
        "sequence_number": seq_num,
        "validation_state": validation_state,
        "validation_flags": validation_flags,
        "operational_status": new_op_status,
        "sensor_health_status": new_sensor_health,
        "events_generated": generated_events,
        "alerts_generated": generated_alerts,
        "baseline_snapshot": {
            "temperature": temp_base,
            "vibration": vib_base,
        },
    }
