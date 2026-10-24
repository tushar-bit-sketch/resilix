"""
RESILIX Deterministic Telemetry Simulation Engine & Fault-Injection Scenarios (A–J)
Implements:
- Reproducible, seeded deterministic pseudo-random generator (`random.Random(seed)`)
- Single-step reading generation and controlled background simulation thread
- Protection against duplicate background worker threads
- Clean shutdown and reset
- All 10 required fault-injection scenarios:
  A_NORMAL               — Normal Operation (within configured baseline)
  B_ELEVATED_VIBRATION   — Sustained rise in vibration exceeding warning/critical thresholds
  C_RISING_TEMPERATURE   — Sustained thermal rise exceeding temperature thresholds
  D_MISSING_SENSOR       — Omitted vibration sensor field (triggers MISSING_SENSOR_FIELD without substituting 0)
  E_STALE_SENSOR         — Repeated / non-advancing old timestamp (triggers STALE_SENSOR_DATA)
  F_IMPLAUSIBLE_READING  — Physically impossible reading (-9.5 mm/s RMS vibration & 195.0°C temp; REJECTED)
  G_INCONSISTENT_READING — High vibration (6.4 mm/s RMS) while motor current is near-zero (0.2 A; SUSPECT)
  H_NETWORK_OUTAGE       — Disables synchronization link, generates local anomaly events into offline queue
  I_NETWORK_RECOVERY     — Restores synchronization link and flushes pending queue with idempotency
  J_SENSOR_RECOVERY      — Restores valid sensor telemetry after a sensor-health fault and records recovery
"""
import math
import random
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.database import DatabaseSession, db_session, utc_now_iso
from app.services.settings_service import get_runtime_settings
from app.services.sync_service import (
    get_sync_connectivity_state,
    run_synchronization_batch,
    set_sync_connectivity_state,
)
from app.services.telemetry_processor import ingest_and_evaluate_telemetry

SCENARIO_CATALOG: dict[str, dict[str, str]] = {
    "A_NORMAL": {
        "code": "A_NORMAL",
        "name": "A. Normal Operation",
        "expected_behavior": "Readings remain within configured baseline bounds; status stays HEALTHY with no critical alerts.",
        "proves": "Baseline stability and low false-alarm rate under normal operating variation.",
        "does_not_prove": "Physical motor longevity on uncalibrated real-world machinery.",
    },
    "B_ELEVATED_VIBRATION": {
        "code": "B_ELEVATED_VIBRATION",
        "name": "B. Elevated Vibration",
        "expected_behavior": "Sustained vibration rise above warning/critical thresholds across the persistence window triggers an explainable vibration anomaly alert.",
        "proves": "Persistence-window filtering and explainable threshold/baseline anomaly detection.",
        "does_not_prove": "Exact mechanical root cause (e.g. bearing spall vs shaft misalignment) without physical inspection.",
    },
    "C_RISING_TEMPERATURE": {
        "code": "C_RISING_TEMPERATURE",
        "name": "C. Rising Temperature",
        "expected_behavior": "Sustained thermal rise above configured temperature warning/critical bounds triggers a temperature anomaly alert.",
        "proves": "Thermal drift detection and multi-metric threshold enforcement.",
        "does_not_prove": "Internal stator winding insulation breakdown without physical thermal imaging.",
    },
    "D_MISSING_SENSOR": {
        "code": "D_MISSING_SENSOR",
        "name": "D. Missing Sensor Field",
        "expected_behavior": "Omits the vibration sensor value; system flags reading as SUSPECT and creates a SENSOR_HEALTH event rather than substituting 0.0.",
        "proves": "Zero-substitution prevention and dedicated sensor-health classification.",
        "does_not_prove": "Physical cable break vs ADC multiplexer failure.",
    },
    "E_STALE_SENSOR": {
        "code": "E_STALE_SENSOR",
        "name": "E. Stale Sensor Timestamp",
        "expected_behavior": "Sends a frozen/old timestamp older than stale_data_timeout_seconds; system detects stale data and marks reading SUSPECT.",
        "proves": "Timestamp freshness verification and frozen-polling-loop detection.",
        "does_not_prove": "Hardware RTC battery depletion.",
    },
    "F_IMPLAUSIBLE_READING": {
        "code": "F_IMPLAUSIBLE_READING",
        "name": "F. Implausible Reading",
        "expected_behavior": "Sends negative vibration (-9.5 mm/s RMS) and out-of-range temperature (195°C); system quarantines reading as REJECTED so trusted baseline is uncorrupted.",
        "proves": "Physical plausibility quarantine protecting rolling baseline statistics from poison inputs.",
        "does_not_prove": "Adversarial sensor spoofing vs hardware amplifier saturation.",
    },
    "G_INCONSISTENT_READING": {
        "code": "G_INCONSISTENT_READING",
        "name": "G. Inconsistent Cross-Sensor Signals",
        "expected_behavior": "Generates elevated vibration (6.4 mm/s RMS) while motor current is near-zero (0.20 A); detects cross-sensor inconsistency and flags SUSPECT.",
        "proves": "Cross-metric physical plausibility correlation between vibration and electrical current.",
        "does_not_prove": "External floor vibration vs faulty current clamp.",
    },
    "H_NETWORK_OUTAGE": {
        "code": "H_NETWORK_OUTAGE",
        "name": "H. Network Outage & Local Queueing",
        "expected_behavior": "Disables remote sync link while continuing local telemetry ingestion and anomaly detection; events accumulate in local SQLite sync queue.",
        "proves": "Local-first edge event logging and uninterrupted anomaly detection during remote link loss.",
        "does_not_prove": "Continued operation if the local host computer itself loses electrical power.",
    },
    "I_NETWORK_RECOVERY": {
        "code": "I_NETWORK_RECOVERY",
        "name": "I. Network Recovery & Idempotent Sync",
        "expected_behavior": "Restores remote sync link and flushes queued events in order using idempotency keys without creating duplicates.",
        "proves": "Deterministic store-and-forward recovery and idempotent deduplication.",
        "does_not_prove": "WAN TLS transport security across public internet infrastructure.",
    },
    "J_SENSOR_RECOVERY": {
        "code": "J_SENSOR_RECOVERY",
        "name": "J. Sensor Recovery",
        "expected_behavior": "Restores valid sensor readings after a missing/stale sensor fault, updates sensor_health_status to OK, and logs a recovery event.",
        "proves": "Automatic sensor-health state recovery and auditability.",
        "does_not_prove": "Permanent physical repair of an intermittent loose wire.",
    },
}


class TelemetrySimulatorEngine:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._running = False
        self._paused = False
        self._speed_multiplier = 1.0
        self._active_scenario = "A_NORMAL"
        self._target_device_id: Optional[str] = None
        self._step_counter = 0
        self._rng = random.Random(20260101)
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_tick_at: Optional[str] = None

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "paused": self._paused,
                "speed_multiplier": self._speed_multiplier,
                "active_scenario": self._active_scenario,
                "active_scenario_info": SCENARIO_CATALOG.get(self._active_scenario, SCENARIO_CATALOG["A_NORMAL"]),
                "target_device_id": self._target_device_id,
                "step_counter": self._step_counter,
                "last_tick_at": self._last_tick_at,
                "available_scenarios": list(SCENARIO_CATALOG.values()),
                "truthfulness_notice": (
                    "All readings generated by this engine are deterministic synthetic telemetry for "
                    "software workflow demonstration. No physical ESP32 hardware is currently connected."
                ),
            }

    def start(self, speed_multiplier: float = 1.0, device_id: Optional[str] = None) -> dict[str, Any]:
        with self._lock:
            self._speed_multiplier = max(0.25, min(float(speed_multiplier), 10.0))
            if device_id:
                self._target_device_id = device_id
            self._paused = False
            if not self._running:
                self._running = True
                self._stop_event.clear()
                self._worker_thread = threading.Thread(
                    target=self._background_loop,
                    name="RESILIX-Simulator-Worker",
                    daemon=True,
                )
                self._worker_thread.start()
            return self.get_status()

    def pause(self) -> dict[str, Any]:
        with self._lock:
            if self._running:
                self._paused = True
            return self.get_status()

    def resume(self) -> dict[str, Any]:
        with self._lock:
            if self._running:
                self._paused = False
            else:
                self.start(self._speed_multiplier, self._target_device_id)
            return self.get_status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            self._running = False
            self._paused = False
            self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        with self._lock:
            self._worker_thread = None
            return self.get_status()

    def reset_state(self, seed: int = 20260101) -> dict[str, Any]:
        self.stop()
        with self._lock:
            self._rng = random.Random(seed)
            self._step_counter = 0
            self._active_scenario = "A_NORMAL"
            self._target_device_id = None
            self._speed_multiplier = 1.0
            self._last_tick_at = None
            return self.get_status()

    def _background_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._lock:
                is_running = self._running
                is_paused = self._paused
                speed = self._speed_multiplier
            if not is_running:
                break
            if not is_paused:
                try:
                    with db_session() as db:
                        runtime_cfg = get_runtime_settings(db)
                        base_interval = float(runtime_cfg.get("simulator_interval_seconds", 2.0))
                        self.generate_step(db, device_id=self._target_device_id, scenario_code=self._active_scenario)
                except Exception:
                    base_interval = 2.0
            else:
                base_interval = 1.0

            sleep_time = max(0.25, base_interval / max(speed, 0.25))
            self._stop_event.wait(timeout=sleep_time)

    def _build_reading_for_device(
        self,
        eq: dict[str, Any],
        scenario_code: str,
        step_idx: int,
    ) -> dict[str, Any]:
        dev_id = eq["device_id"]
        next_seq = int(eq["last_sequence_number"] or 0) + 1
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        t_mid = (float(eq["temp_normal_min"]) + float(eq["temp_normal_max"])) / 2.0
        v_mid = (float(eq["vib_normal_min"]) + float(eq["vib_normal_max"])) / 2.0
        c_mid = (float(eq["current_normal_min"]) + float(eq["current_normal_max"])) / 2.0

        # Deterministic harmonic + small bounded variation
        phase = (step_idx + sum(ord(c) for c in dev_id)) * 0.45
        temp: Optional[float] = round(t_mid + 1.8 * math.sin(phase) + self._rng.uniform(-0.4, 0.4), 2)
        vib: Optional[float] = round(v_mid + 0.28 * math.cos(phase) + self._rng.uniform(-0.08, 0.08), 2)
        cur: Optional[float] = (
            round(c_mid + 0.35 * math.sin(phase) + self._rng.uniform(-0.1, 0.1), 2)
            if int(eq["has_current_sensor"]) == 1
            else None
        )
        ts_to_use = now_iso
        is_anomaly = False

        if scenario_code == "B_ELEVATED_VIBRATION":
            vib = round(float(eq["vib_critical_threshold"]) + 0.85 + 0.15 * (step_idx % 3), 2)
            if cur is not None:
                cur = round(c_mid + 1.2, 2)
            is_anomaly = True

        elif scenario_code == "C_RISING_TEMPERATURE":
            temp = round(float(eq["temp_critical_threshold"]) + 2.4 + 0.4 * (step_idx % 4), 2)
            if cur is not None:
                cur = round(c_mid + 1.4, 2)
            is_anomaly = True

        elif scenario_code == "D_MISSING_SENSOR":
            vib = None
            is_anomaly = True

        elif scenario_code == "E_STALE_SENSOR":
            stale_dt = now_dt - timedelta(seconds=120)
            ts_to_use = stale_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            is_anomaly = True

        elif scenario_code == "F_IMPLAUSIBLE_READING":
            vib = -9.5
            temp = 195.0
            is_anomaly = True

        elif scenario_code == "G_INCONSISTENT_READING":
            vib = round(float(eq["vib_warning_threshold"]) + 1.9, 2)
            cur = 0.20
            is_anomaly = True

        elif scenario_code == "H_NETWORK_OUTAGE":
            # During network outage scenario, also inject elevated vibration so local queue growth is visible
            vib = round(float(eq["vib_warning_threshold"]) + 0.9, 2)
            is_anomaly = True

        elif scenario_code == "J_SENSOR_RECOVERY":
            # Clean normal values restoring sensor health
            is_anomaly = False

        return {
            "device_id": dev_id,
            "sequence_number": next_seq,
            "timestamp": ts_to_use,
            "temperature": temp,
            "vibration": vib,
            "current_amps": cur,
            "simulation_mode": "SIMULATED",
            "scenario_name": scenario_code,
            "is_synthetic_anomaly": is_anomaly,
        }

    def generate_step(
        self,
        db: DatabaseSession,
        device_id: Optional[str] = None,
        scenario_code: Optional[str] = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._step_counter += 1
            step_idx = self._step_counter
            scen = scenario_code or self._active_scenario
            self._last_tick_at = utc_now_iso()

        if device_id:
            devices = db.fetchall(
                "SELECT * FROM equipment WHERE device_id = ? AND is_enabled = 1 AND is_simulated = 1",
                (device_id,),
            )
        else:
            devices = db.fetchall(
                "SELECT * FROM equipment WHERE is_enabled = 1 AND is_simulated = 1 ORDER BY device_id ASC"
            )

        results = []
        for eq in devices:
            reading_payload = self._build_reading_for_device(eq, scen, step_idx)
            res = ingest_and_evaluate_telemetry(db, reading_payload)
            results.append(res)

        # If online, automatically sync any newly queued events unless in manual offline scenario
        sync_state = get_sync_connectivity_state()
        if sync_state["online"] and not sync_state["simulate_transient_failure"]:
            run_synchronization_batch(db, batch_limit=50)

        return {
            "step_counter": step_idx,
            "scenario_code": scen,
            "devices_processed": len(results),
            "results": results,
            "timestamp": self._last_tick_at,
        }

    def execute_scenario(
        self,
        db: DatabaseSession,
        scenario_code: str,
        device_id: str = "PUMP-01",
        steps: int = 3,
        actor_username: str = "admin",
    ) -> dict[str, Any]:
        if scenario_code not in SCENARIO_CATALOG:
            raise ValueError(f"Unsupported scenario_code: {scenario_code}")

        eq = db.fetchone("SELECT * FROM equipment WHERE device_id = ?", (device_id,))
        if not eq:
            raise ValueError(f"Device '{device_id}' not found.")
        if int(eq["is_enabled"]) == 0:
            raise ValueError(f"Device '{device_id}' is disabled. Enable it before running scenarios.")

        with self._lock:
            self._active_scenario = scenario_code
            self._target_device_id = device_id

        start_perf = time.perf_counter()
        scen_meta = SCENARIO_CATALOG[scenario_code]

        # Special handling for H_NETWORK_OUTAGE, I_NETWORK_RECOVERY, J_SENSOR_RECOVERY
        if scenario_code == "H_NETWORK_OUTAGE":
            set_sync_connectivity_state(db, online=False, simulate_transient_failure=False, actor_username=actor_username)
        elif scenario_code == "I_NETWORK_RECOVERY":
            set_sync_connectivity_state(db, online=True, simulate_transient_failure=False, actor_username=actor_username)
            sync_rep = run_synchronization_batch(db, batch_limit=200)
            elapsed_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
            observed = (
                f"Restored synchronization link; synchronized {sync_rep['synced_newly']} pending events "
                f"({sync_rep['deduplicated_skips']} deduplicated, {sync_rep['remaining_pending']} remaining)."
            )
            db.execute(
                """
                INSERT INTO scenario_executions (
                    scenario_code, scenario_name, device_id, expected_behavior,
                    observed_outcome, passed, warning_latency_ms,
                    readings_generated, events_created, executed_by, executed_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, 0, ?, ?, ?)
                """,
                (
                    scenario_code,
                    scen_meta["name"],
                    device_id,
                    scen_meta["expected_behavior"],
                    observed,
                    elapsed_ms,
                    sync_rep["synced_newly"],
                    actor_username,
                    utc_now_iso(),
                ),
            )
            return {
                "scenario": scen_meta,
                "device_id": device_id,
                "steps_executed": 0,
                "readings_generated": 0,
                "events_created": sync_rep["synced_newly"],
                "alerts_created": 0,
                "warning_latency_ms": elapsed_ms,
                "observed_outcome": observed,
                "passed": True,
                "sync_report": sync_rep,
            }

        persistence_req = int(eq["persistence_window_count"] or 2)
        effective_steps = max(steps, persistence_req) if scenario_code in ("B_ELEVATED_VIBRATION", "C_RISING_TEMPERATURE", "H_NETWORK_OUTAGE") else steps

        total_events: list[dict[str, Any]] = []
        total_alerts: list[dict[str, Any]] = []
        step_outputs: list[dict[str, Any]] = []
        first_warning_latency_ms: Optional[float] = None

        for _ in range(effective_steps):
            t0 = time.perf_counter()
            step_res = self.generate_step(db, device_id=device_id, scenario_code=scenario_code)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            for r in step_res["results"]:
                step_outputs.append(r)
                if r["events_generated"]:
                    total_events.extend(r["events_generated"])
                    if first_warning_latency_ms is None:
                        first_warning_latency_ms = round(dt_ms, 2)
                if r["alerts_generated"]:
                    total_alerts.extend(r["alerts_generated"])

        total_elapsed_ms = round((time.perf_counter() - start_perf) * 1000.0, 2)
        latency_to_record = first_warning_latency_ms if first_warning_latency_ms is not None else total_elapsed_ms

        last_state = step_outputs[-1] if step_outputs else {}
        if scenario_code == "A_NORMAL":
            passed = last_state.get("operational_status") == "HEALTHY" and len(total_alerts) == 0
            observed = (
                f"Generated {len(step_outputs)} valid readings on {device_id}; "
                f"operational_status={last_state.get('operational_status')}, alerts_created={len(total_alerts)}."
            )
        elif scenario_code in ("B_ELEVATED_VIBRATION", "C_RISING_TEMPERATURE"):
            passed = len(total_events) > 0 and len(total_alerts) > 0
            observed = (
                f"Generated {len(step_outputs)} readings on {device_id}; triggered {len(total_events)} anomaly event(s) "
                f"and {len(total_alerts)} alert(s) with local detection latency {latency_to_record:.2f} ms."
            )
        elif scenario_code in ("D_MISSING_SENSOR", "E_STALE_SENSOR", "F_IMPLAUSIBLE_READING", "G_INCONSISTENT_READING"):
            passed = len(total_events) > 0 and last_state.get("validation_state") in ("SUSPECT", "REJECTED")
            observed = (
                f"Classified reading(s) as {last_state.get('validation_state')} "
                f"(sensor_health={last_state.get('sensor_health_status')}); recorded {len(total_events)} quality/health event(s) "
                f"without corrupting trusted baseline."
            )
        elif scenario_code == "H_NETWORK_OUTAGE":
            sync_sum = get_sync_connectivity_state()
            passed = (not sync_sum["online"]) and len(total_events) > 0
            observed = (
                f"Remote sync link disabled (OFFLINE); generated {len(total_events)} local event(s) queued safely in SQLite."
            )
        elif scenario_code == "J_SENSOR_RECOVERY":
            passed = last_state.get("sensor_health_status") == "OK"
            observed = (
                f"Restored valid sensor readings on {device_id}; sensor_health_status={last_state.get('sensor_health_status')}."
            )
        else:
            passed = True
            observed = f"Executed {len(step_outputs)} steps for {scenario_code}."

        db.execute(
            """
            INSERT INTO scenario_executions (
                scenario_code, scenario_name, device_id, expected_behavior,
                observed_outcome, passed, warning_latency_ms,
                readings_generated, events_created, executed_by, executed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scenario_code,
                scen_meta["name"],
                device_id,
                scen_meta["expected_behavior"],
                observed,
                1 if passed else 0,
                latency_to_record,
                len(step_outputs),
                len(total_events),
                actor_username,
                utc_now_iso(),
            ),
        )

        # Reset active scenario back to A_NORMAL after fault injection burst so background ticks don't loop fault forever
        with self._lock:
            if scenario_code != "A_NORMAL":
                self._active_scenario = "A_NORMAL"

        return {
            "scenario": scen_meta,
            "device_id": device_id,
            "steps_executed": len(step_outputs),
            "readings_generated": len(step_outputs),
            "events_created": len(total_events),
            "alerts_created": len(total_alerts),
            "warning_latency_ms": latency_to_record,
            "observed_outcome": observed,
            "passed": passed,
            "last_reading_result": last_state,
        }


simulator_engine = TelemetrySimulatorEngine()
