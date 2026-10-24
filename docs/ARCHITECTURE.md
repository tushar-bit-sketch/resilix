# RESILIX Technical Architecture Document
**Secure Predictive Infrastructure Resilience System**  
*Seva First Innovation Challenge 2026 | Surakshit Bharat — Security & Resilience*

---

## 1. Telemetry Ingestion Pipeline
Telemetry enters RESILIX through two paths that share the exact same validation and persistence function (`ingest_and_evaluate_telemetry` in `backend/app/services/telemetry_processor.py`):
1. **Deterministic Simulation Engine (`backend/app/simulator/engine.py`)**: Uses a seeded pseudo-random generator (`random.Random(20260101)`) and harmonic baseline functions to produce reproducible readings for `PUMP-01`, `MOTOR-02`, and `FAN-03`, or to inject controlled faults across Scenarios `A_NORMAL` through `J_SENSOR_RECOVERY`.
2. **REST Ingestion Endpoint (`POST /api/v1/equipment/ingest`)**: Accepts JSON payloads validated by `TelemetryIngestRequest` (`device_id`, `sequence_number`, `timestamp`, `temperature`, `vibration`, `current_amps`, `simulation_mode`, `scenario_name`).

---

## 2. Pre-Analytics Validation & Sensor-Data Quality
Before any reading is allowed to update equipment operational status or rolling baselines, it passes through a 5-stage validation gate:
1. **Sequence Replay / Duplicate Check**: Compares `sequence_number` against `equipment.last_sequence_number`. Non-increasing sequence numbers are flagged `REPLAYED_OR_DUPLICATE_SEQUENCE` and marked `REJECTED`.
2. **Timestamp Freshness Check**: Parses ISO-8601 UTC timestamps and compares age against runtime `stale_data_timeout_seconds` (default `30s`) and the previous reading timestamp. Stale or frozen timestamps are flagged `STALE_TIMESTAMP` and marked `SUSPECT`.
3. **Missing Channel Check (Zero-Substitution Prevention)**: If `temperature` or `vibration` (or `current_amps` during missing-sensor tests) is `null`, RESILIX never coerces the missing value to `0.0`. Instead, it flags `MISSING_SENSOR_FIELDS`, marks the reading `SUSPECT`, sets `sensor_health_status = 'MISSING_SENSOR'`, and preserves the last known valid measurement on the equipment overview.
4. **Physical Plausibility Bounds**: Readings outside physical transducer limits (e.g., negative vibration `< 0.0 mm/s RMS` or extreme temperature `> 130°C`) are marked `REJECTED` (`IMPLAUSIBLE_OUT_OF_RANGE`).
5. **Cross-Sensor Consistency**: Checks physical correlation between vibration and electrical current (e.g., high vibration exceeding warning thresholds while motor current is near-zero `< 0.8 A`). Inconsistent combinations are marked `SUSPECT` (`INCONSISTENT_CROSS_SENSOR_SIGNALS`).

---

## 3. Explainable Anomaly Detection Engine
Only readings with `validation_state == 'ACCEPTED'` enter the anomaly detection stage:
- **Rolling Baseline Statistics**: `compute_baseline_statistics` queries the last `N` (`baseline_window_size`, default `25`) `ACCEPTED` readings for the device and computes `mean`, `std`, `median`, `min`, and `max` using NumPy.
- **Persistence Window Filtering**: To prevent single-sample spikes from causing alert fatigue, threshold and baseline rules require `persistence_window_count` (default `2`) consecutive `ACCEPTED` readings exceeding the threshold before firing an anomaly event.
- **Explainability**: Every generated anomaly records `observed_value`, `baseline_value`, `threshold_value`, `deviation_score` (in standard deviations $\sigma$, explicitly labelled as a statistical deviation score rather than a failure probability), `persistence_count`, `rule_id`, human-readable `explanation`, and `recommended_action`.
- **Alert Grouping & Lifecycle**: `upsert_or_group_alert` checks if an active (`OPEN` or `ACKNOWLEDGED`) alert already exists for the same `(device_id, rule_id, metric)`. If so, it increments `occurrence_count` and updates `last_seen_at` rather than creating duplicate alerts. Operators can transition alerts from `OPEN -> ACKNOWLEDGED -> RESOLVED` (with a mandatory resolution note).

---

## 4. Event Persistence & SHA-256 Append-Only Hash Chain
Implemented in `backend/app/services/integrity.py`:
- Every system, anomaly, sensor-health, authentication, synchronization, and operator event is written to the `events` table with a monotonically increasing `sequence_index`.
- `build_canonical_event_payload` serializes 12 core event attributes into a deterministic, key-sorted JSON string (`separators=(",", ":")`).
- `compute_chain_hash` calculates:
  $$\text{event\_hash}_i = \text{SHA256}(\text{previous\_hash}_{i-1} \mathbin{\Vert} \text{"|"} \mathbin{\Vert} \text{canonical\_payload}_i)$$
  where $\text{previous\_hash}_0 = \text{GENESIS\_HASH}$ (`64` zeros).
- `verify_entire_event_chain` walks all records from index `1..N`, recomputing canonical payloads from the live `events` table columns and verifying both `previous_hash` linkage and `event_hash` equality. Any modification to an event column or chain record immediately triggers `INTEGRITY_COMPROMISED`.

---

## 5. Offline Queue & Idempotent Synchronization
Implemented in `backend/app/services/sync_service.py`:
- When an event is created, a corresponding row is inserted into `sync_queue_items` in state `PENDING` with a deterministic idempotency key `IDEMP-{event_id}-{event_hash[:16]}`.
- When the synchronization adapter is `OFFLINE`, local telemetry ingestion, anomaly detection, and hash-chain logging continue uninterrupted while `PENDING` items accumulate in SQLite.
- When `ONLINE`, `run_synchronization_batch` processes `PENDING` and retry-eligible `FAILED` items in FIFO order:
  1. Verifies single-event cryptographic integrity (`verify_single_event_integrity`) before transmission.
  2. Checks `sync_acknowledgements` (`SIMULATED_REMOTE_SINK_V1`) for an existing `idempotency_key` or `event_id` to guarantee zero duplicate remote insertions on repeated sync runs.
  3. On transient failure (`simulate_transient_failure=True`), increments `attempt_count` and schedules `next_retry_at` using exponential backoff (`base * 2^(attempt-1)`).

---

## 6. Authentication, Authorization & Security Controls
Implemented in `backend/app/security/auth.py`:
- **Password Hashing**: Uses `cryptography.hazmat.primitives.kdf.scrypt.Scrypt` (`N=16384, r=8, p=1`, 128-bit random salt) verified in constant time.
- **Session Management**: `create_user_session` generates a 256-bit cryptographically random token, stores only its `SHA-256` hash in `user_sessions`, and issues both an `HttpOnly`, `SameSite=Lax` cookie (`resilix_session`) and a Bearer token for API clients.
- **Rate Limiting**: Sliding-window rate limiter blocks brute-force login attempts after `5` failures within `60` seconds (`HTTP 429 Too Many Requests`).
- **Role-Based Access Control (RBAC)**: `get_current_user` protects all authenticated endpoints; `require_admin` restricts equipment registration, configuration updates, settings modifications, and demo resets to `admin` users (`HTTP 403 Forbidden` for `operator`).
- **Audit Logging**: All authentication events, RBAC denials, alert state changes, scenario triggers, integrity checks, and settings changes are recorded in `audit_logs`.

---

## 7. Relational Database Schema (13 Entities)
Defined in `backend/app/models/schema.py`:
1. `users`: User accounts, roles (`admin`, `operator`), Scrypt password hashes, login failure counters.
2. `user_sessions`: Server-side session ledger with SHA-256 token hashes, CSRF tokens, expiration, and revocation flags.
3. `equipment`: Registered equipment metadata, operational & sensor-health status, and per-device normal/warning/critical thresholds.
4. `sensor_readings`: Timestamped telemetry frames with `validation_state` (`ACCEPTED`, `SUSPECT`, `REJECTED`) and `validation_flags`.
5. `events`: Unified event history across all categories with explainability fields (`observed_value`, `baseline_value`, `threshold_value`, `deviation_score`, `rule_id`, `explanation`, `recommended_action`).
6. `event_integrity_records`: Append-only SHA-256 hash chain (`chain_index`, `canonical_payload`, `previous_hash`, `event_hash`).
7. `alerts`: Alert lifecycle records (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`), occurrence grouping counts, and operator resolution notes.
8. `sync_queue_items`: Local store-and-forward queue (`PENDING`, `SYNCING`, `SYNCED`, `FAILED`), attempt counts, backoff timestamps, and idempotency keys.
9. `sync_acknowledgements`: Simulated remote sink ledger enforcing unique idempotency keys.
10. `audit_logs`: Security and operator audit trail.
11. `maintenance_notes`: Per-equipment inspection, calibration, repair, and observation notes.
12. `application_settings`: Persistent key-value runtime configuration.
13. `scenario_executions`: Validation history of executed fault-injection scenarios with measured warning latency and pass/fail outcomes.
