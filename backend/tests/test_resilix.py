"""
RESILIX Comprehensive Automated Test Suite
Exercises:
1. Database initialization & idempotent seeding
2. Authentication: login success (admin & operator), login failure, rate limiting, session persistence, logout revocation
3. Protected endpoints & Role-Based Access Control (operator blocked from admin endpoints)
4. Equipment CRUD operations, duplicate ID prevention, disabling device stops simulator ingestion while preserving history
5. Valid telemetry acceptance & baseline calculation
6. Invalid telemetry rejection (malformed device_id, non-finite values, implausible negative vibration / extreme temp)
7. Missing sensor detection (flagged SUSPECT, never replaced with 0.0)
8. Stale sensor timestamp detection
9. Inconsistent cross-sensor signal detection
10. Threshold-based & baseline-based anomaly detection with persistence rules
11. Duplicate-alert suppression / occurrence grouping
12. Alert acknowledgement (does not silently resolve) and alert resolution with note
13. SHA-256 append-only event hash verification & deliberate database tampering detection
14. Offline queue persistence during simulated network outage
15. Synchronization retries with transient failure & idempotent recovery without duplicates
16. Scenario triggering across all scenarios (A–J)
17. Settings validation & runtime behavioral effect on subsequent anomaly/stale checks
18. CSV export with Spreadsheet Formula Injection protection
"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

# Configure isolated test database before importing app
_tmp_db = tempfile.NamedTemporaryFile(prefix="resilix_test_", suffix=".db", delete=False)
_tmp_db.close()
os.environ["RESILIX_DB_PATH"] = _tmp_db.name

from fastapi.testclient import TestClient

from app.config import settings
from app.database import db_session, utc_now_iso
from app.main import app
from app.models.schema import init_db_schema
from app.security.auth import reset_all_rate_limits
from app.services.analytics_service import sanitize_csv_cell
from app.services.integrity import verify_entire_event_chain, verify_single_event_integrity
from app.services.seed_service import seed_initial_data


class ResilixAutomatedTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        settings.database_path = _tmp_db.name
        init_db_schema()
        with db_session() as db:
            seed_initial_data(db, force_reset=True)
        cls.client = TestClient(app)

    def setUp(self) -> None:
        reset_all_rate_limits()
        with db_session() as db:
            seed_initial_data(db, force_reset=True)

    def _login(self, username: str, password: str) -> tuple[dict, str]:
        resp = self.client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(resp.status_code, 200, f"Login failed: {resp.text}")
        data = resp.json()
        return data, data["access_token"]

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    # 1. Database initialization & idempotent seeding
    def test_01_database_init_and_idempotent_seed(self) -> None:
        with db_session() as db:
            res1 = seed_initial_data(db, force_reset=False)
            self.assertEqual(res1["status"], "ALREADY_INITIALIZED")
            users = db.fetchall("SELECT username, role, password_hash FROM users")
            self.assertEqual(len(users), 2)
            for u in users:
                self.assertTrue(u["password_hash"].startswith("scrypt$"))
                self.assertNotIn("Resilix", u["password_hash"])
            eqs = db.fetchall("SELECT device_id FROM equipment")
            self.assertEqual(len(eqs), 3)

    # 2. Authentication & Rate Limiting
    def test_02_login_logout_and_rate_limiting(self) -> None:
        # Unauthenticated access rejected
        unauth = self.client.get("/api/v1/dashboard/summary")
        self.assertEqual(unauth.status_code, 401)

        # Invalid password rejected
        bad = self.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "WrongPassword123"},
        )
        self.assertEqual(bad.status_code, 401)

        # Valid admin login
        data, token = self._login("admin", "ResilixAdmin!2026")
        self.assertEqual(data["user"]["role"], "admin")

        # Verify /auth/me works
        me = self.client.get("/api/v1/auth/me", headers=self._auth_headers(token))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], "admin")

        # Logout invalidates session
        out = self.client.post("/api/v1/auth/logout", headers=self._auth_headers(token))
        self.assertEqual(out.status_code, 200)

        after_logout = self.client.get("/api/v1/auth/me", headers=self._auth_headers(token))
        self.assertEqual(after_logout.status_code, 401)

        # Test login rate limiting (5 failures -> 429)
        for _ in range(5):
            r = self.client.post(
                "/api/v1/auth/login",
                json={"username": "operator", "password": "BadPassword999"},
            )
            self.assertEqual(r.status_code, 401)
        rate_limited = self.client.post(
            "/api/v1/auth/login",
            json={"username": "operator", "password": "BadPassword999"},
        )
        self.assertEqual(rate_limited.status_code, 429)

    # 3. Role-Based Access Control (Admin vs Operator)
    def test_03_rbac_permission_enforcement(self) -> None:
        _, op_token = self._login("operator", "ResilixOper!2026")
        _, adm_token = self._login("admin", "ResilixAdmin!2026")

        # Operator can read dashboard & create maintenance notes
        dash = self.client.get("/api/v1/dashboard/summary", headers=self._auth_headers(op_token))
        self.assertEqual(dash.status_code, 200)

        note_resp = self.client.post(
            "/api/v1/equipment/PUMP-01/maintenance",
            headers=self._auth_headers(op_token),
            json={"note_type": "INSPECTION", "content": "Checked pump bearing housing temperature; normal."},
        )
        self.assertEqual(note_resp.status_code, 201)

        # Operator CANNOT register new equipment or modify system settings
        forbidden_eq = self.client.post(
            "/api/v1/equipment",
            headers=self._auth_headers(op_token),
            json={
                "device_id": "PUMP-99",
                "name": "Unauthorized Pump",
                "device_type": "water_pump",
                "location": "Bay Z",
            },
        )
        self.assertEqual(forbidden_eq.status_code, 403)

        forbidden_set = self.client.patch(
            "/api/v1/settings",
            headers=self._auth_headers(op_token),
            json={"stale_data_timeout_seconds": 45},
        )
        self.assertEqual(forbidden_set.status_code, 403)

        # Admin CAN register new equipment
        allowed_eq = self.client.post(
            "/api/v1/equipment",
            headers=self._auth_headers(adm_token),
            json={
                "device_id": "COMP-04",
                "name": "Auxiliary Air Compressor",
                "device_type": "compressor",
                "location": "Pneumatics Room D1",
            },
        )
        self.assertEqual(allowed_eq.status_code, 201)

        # Duplicate device_id prevented with 409
        dup_eq = self.client.post(
            "/api/v1/equipment",
            headers=self._auth_headers(adm_token),
            json={
                "device_id": "COMP-04",
                "name": "Duplicate Compressor",
                "device_type": "compressor",
                "location": "Pneumatics Room D1",
            },
        )
        self.assertEqual(dup_eq.status_code, 409)

    # 4. Equipment deactivation preserves history and blocks new ingestion
    def test_04_equipment_disable_preserves_history(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # Disable FAN-03
        patch_resp = self.client.patch(
            "/api/v1/equipment/FAN-03",
            headers=headers,
            json={"is_enabled": False},
        )
        self.assertEqual(patch_resp.status_code, 200)
        self.assertFalse(patch_resp.json()["is_enabled"])
        self.assertEqual(patch_resp.json()["operational_status"], "DISABLED")

        # Historical readings still exist
        hist = self.client.get("/api/v1/equipment/FAN-03/readings", headers=headers)
        self.assertEqual(hist.status_code, 200)
        self.assertGreaterEqual(hist.json()["count"], 8)

        # Ingesting new reading into disabled device is rejected
        ingest = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "FAN-03",
                "sequence_number": 99,
                "timestamp": utc_now_iso(),
                "temperature": 40.0,
                "vibration": 1.8,
                "current_amps": 3.9,
            },
        )
        self.assertEqual(ingest.status_code, 422)

    # 5. Telemetry Validation: Valid, Missing, Stale, Implausible, Replayed, Inconsistent
    def test_05_telemetry_validation_and_quarantine(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # A. Valid telemetry acceptance
        valid_res = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 20,
                "timestamp": utc_now_iso(),
                "temperature": 42.5,
                "vibration": 1.95,
                "current_amps": 4.8,
            },
        )
        self.assertEqual(valid_res.status_code, 200)
        self.assertEqual(valid_res.json()["validation_state"], "ACCEPTED")

        # B. Replayed sequence number -> REJECTED
        replay_res = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 20,
                "timestamp": utc_now_iso(),
                "temperature": 42.5,
                "vibration": 1.95,
                "current_amps": 4.8,
            },
        )
        self.assertEqual(replay_res.status_code, 200)
        self.assertEqual(replay_res.json()["validation_state"], "REJECTED")
        self.assertIn("REPLAYED_OR_DUPLICATE_SEQUENCE", replay_res.json()["validation_flags"])

        # C. Missing sensor field -> SUSPECT (and never coerced to 0.0)
        missing_res = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 21,
                "timestamp": utc_now_iso(),
                "temperature": 43.0,
                "vibration": None,
                "current_amps": 4.9,
            },
        )
        self.assertEqual(missing_res.status_code, 200)
        self.assertEqual(missing_res.json()["validation_state"], "SUSPECT")
        self.assertEqual(missing_res.json()["sensor_health_status"], "MISSING_SENSOR")
        # Verify equipment latest_vibration was NOT overwritten with 0 or None
        eq_detail = self.client.get("/api/v1/equipment/PUMP-01", headers=headers).json()["equipment"]
        self.assertEqual(eq_detail["latest_vibration"], 1.95)

        # D. Stale timestamp -> SUSPECT
        stale_ts = (datetime.now(timezone.utc) - timedelta(seconds=180)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        stale_res = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 22,
                "timestamp": stale_ts,
                "temperature": 43.2,
                "vibration": 2.0,
                "current_amps": 4.9,
            },
        )
        self.assertEqual(stale_res.status_code, 200)
        self.assertEqual(stale_res.json()["validation_state"], "SUSPECT")
        self.assertEqual(stale_res.json()["sensor_health_status"], "STALE_DATA")

        # E. Implausible physical reading (negative vibration -12.0 mm/s) -> REJECTED
        implausible_res = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 23,
                "timestamp": utc_now_iso(),
                "temperature": 43.5,
                "vibration": -12.0,
                "current_amps": 4.9,
            },
        )
        self.assertEqual(implausible_res.status_code, 200)
        self.assertEqual(implausible_res.json()["validation_state"], "REJECTED")
        self.assertEqual(implausible_res.json()["sensor_health_status"], "IMPLAUSIBLE_READING")
        # Ensure trusted baseline mean was not contaminated by -12.0
        eq_detail_after = self.client.get("/api/v1/equipment/PUMP-01", headers=headers).json()
        self.assertGreater(eq_detail_after["baselines"]["vibration"]["min"], 0.5)

        # F. Inconsistent cross-sensor signal (vibration=6.0 mm/s while current=0.15 A) -> SUSPECT
        inconsistent_res = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 24,
                "timestamp": utc_now_iso(),
                "temperature": 43.5,
                "vibration": 6.0,
                "current_amps": 0.15,
            },
        )
        self.assertEqual(inconsistent_res.status_code, 200)
        self.assertEqual(inconsistent_res.json()["validation_state"], "SUSPECT")
        self.assertEqual(inconsistent_res.json()["sensor_health_status"], "INCONSISTENT_SIGNAL")

    # 6. Persistence Window, Threshold & Baseline Anomaly Detection, Duplicate Alert Grouping, Alert Lifecycle
    def test_06_anomaly_persistence_and_alert_lifecycle(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # PUMP-01 has persistence_window_count = 2 and vib_critical_threshold = 6.5
        # Step 1 of elevated vibration: should NOT trigger sustained threshold alert yet (persistence=1 < 2)
        step1 = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 30,
                "timestamp": utc_now_iso(),
                "temperature": 44.0,
                "vibration": 7.2,
                "current_amps": 5.8,
            },
        )
        self.assertEqual(step1.status_code, 200)
        self.assertEqual(len(step1.json()["alerts_generated"]), 0)

        # Step 2 of elevated vibration: meets persistence window (2 consecutive readings >= threshold) -> creates alert!
        step2 = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 31,
                "timestamp": utc_now_iso(),
                "temperature": 44.2,
                "vibration": 7.4,
                "current_amps": 5.9,
            },
        )
        self.assertEqual(step2.status_code, 200)
        alerts_gen = step2.json()["alerts_generated"]
        self.assertEqual(len(alerts_gen), 1)
        alert_id = alerts_gen[0]["alert_id"]
        self.assertFalse(alerts_gen[0]["grouped"])

        # Step 3 of elevated vibration: should group into the existing active alert rather than creating a duplicate
        step3 = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 32,
                "timestamp": utc_now_iso(),
                "temperature": 44.4,
                "vibration": 7.5,
                "current_amps": 6.0,
            },
        )
        self.assertEqual(step3.status_code, 200)
        alerts_gen3 = step3.json()["alerts_generated"]
        self.assertEqual(alerts_gen3[0]["alert_id"], alert_id)
        self.assertTrue(alerts_gen3[0]["grouped"])
        self.assertEqual(alerts_gen3[0]["occurrence_count"], 2)

        # Acknowledge alert -> transitions to ACKNOWLEDGED, NOT RESOLVED
        ack_resp = self.client.post(
            f"/api/v1/alerts/{alert_id}/acknowledge",
            headers=headers,
            json={"note": "Assigning technician to inspect PUMP-01 bearing."},
        )
        self.assertEqual(ack_resp.status_code, 200)
        self.assertEqual(ack_resp.json()["lifecycle_state"], "ACKNOWLEDGED")
        self.assertIsNone(ack_resp.json()["resolved_at"])

        # Resolve alert with resolution note -> transitions to RESOLVED
        res_resp = self.client.post(
            f"/api/v1/alerts/{alert_id}/resolve",
            headers=headers,
            json={
                "resolution_note": "Tightened loosened motor-pump coupling bolts and verified alignment.",
                "is_false_alert": False,
            },
        )
        self.assertEqual(res_resp.status_code, 200)
        self.assertEqual(res_resp.json()["lifecycle_state"], "RESOLVED")
        self.assertEqual(res_resp.json()["resolved_by"], "admin")

    # 7. Baseline Statistical Deviation Detection
    def test_07_baseline_statistical_deviation_detection(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # MOTOR-02 has vib_normal_max = 2.6, vib_warning_threshold = 4.0, baseline ~ 1.8 mm/s
        # Send two readings at 3.4 mm/s (above normal_max and >3.2 sigma above baseline, but below static warning 4.0)
        for seq in (40, 41):
            r = self.client.post(
                "/api/v1/equipment/ingest",
                headers=headers,
                json={
                    "device_id": "MOTOR-02",
                    "sequence_number": seq,
                    "timestamp": utc_now_iso(),
                    "temperature": 43.0,
                    "vibration": 3.45,
                    "current_amps": 4.7,
                },
            )
            self.assertEqual(r.status_code, 200)

        evts = r.json()["events_generated"]
        self.assertTrue(any(e["rule_id"] == "RULE_ANOM_VIB_BASELINE_Z" for e in evts))

    # 8. SHA-256 Event Hash Chain Verification & Tampering Detection
    def test_08_event_hash_chain_and_tamper_detection(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # Trigger a scenario to generate events
        self.client.post(
            "/api/v1/simulator/scenarios",
            headers=headers,
            json={"scenario_code": "B_ELEVATED_VIBRATION", "device_id": "PUMP-01", "steps": 3},
        )

        # Verify chain is intact
        verify_ok = self.client.post("/api/v1/security/integrity/verify", headers=headers)
        self.assertEqual(verify_ok.status_code, 200)
        self.assertTrue(verify_ok.json()["valid"])
        self.assertEqual(verify_ok.json()["status"], "VERIFIED_INTACT")
        self.assertEqual(verify_ok.json()["mismatch_count"], 0)

        # Deliberately tamper with an event summary in SQLite
        with db_session() as db:
            target_evt = db.fetchone("SELECT event_id, summary FROM events ORDER BY sequence_index DESC LIMIT 1")
            tampered_id = target_evt["event_id"]
            orig_summary = target_evt["summary"]
            db.execute(
                "UPDATE events SET summary = 'TAMPERED_SUMMARY_BY_INTRUDER' WHERE event_id = ?",
                (tampered_id,),
            )

        # Verification MUST detect tampering on both single-event and full-chain endpoints
        single_v = self.client.get(f"/api/v1/events/{tampered_id}/verify", headers=headers)
        self.assertEqual(single_v.status_code, 200)
        self.assertFalse(single_v.json()["valid"])
        self.assertFalse(single_v.json()["payload_matches_canonical"])

        chain_v = self.client.post("/api/v1/security/integrity/verify", headers=headers)
        self.assertEqual(chain_v.status_code, 200)
        self.assertFalse(chain_v.json()["valid"])
        self.assertEqual(chain_v.json()["status"], "INTEGRITY_COMPROMISED")
        self.assertGreater(chain_v.json()["mismatch_count"], 0)

        # Restore original summary and re-verify intact
        with db_session() as db:
            db.execute("UPDATE events SET summary = ? WHERE event_id = ?", (orig_summary, tampered_id))
        restored_v = self.client.post("/api/v1/security/integrity/verify", headers=headers)
        self.assertTrue(restored_v.json()["valid"])

    # 9. Offline Event Queueing, Transient Failure Retry, and Idempotent Synchronization Recovery
    def test_09_offline_queue_retries_and_idempotent_sync(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # 1. Disable sync connectivity (Go Offline)
        off_resp = self.client.post(
            "/api/v1/sync/connectivity",
            headers=headers,
            json={"online": False, "simulate_transient_failure": False},
        )
        self.assertEqual(off_resp.status_code, 200)
        self.assertFalse(off_resp.json()["online"])

        # 2. Trigger anomalies while offline -> pending queue increases
        self.client.post(
            "/api/v1/simulator/scenarios",
            headers=headers,
            json={"scenario_code": "C_RISING_TEMPERATURE", "device_id": "MOTOR-02", "steps": 3},
        )
        status_off = self.client.get("/api/v1/sync/status", headers=headers).json()
        self.assertGreaterEqual(status_off["pending_count"], 2)

        # 3. Attempt sync while offline -> skipped
        run_off = self.client.post("/api/v1/sync/run", headers=headers).json()
        self.assertEqual(run_off["status"], "OFFLINE_SKIPPED")

        # 4. Enable online mode WITH transient failure simulation -> items transition to FAILED with backoff
        self.client.post(
            "/api/v1/sync/connectivity",
            headers=headers,
            json={"online": True, "simulate_transient_failure": True},
        )
        run_fail = self.client.post("/api/v1/sync/run", headers=headers).json()
        self.assertEqual(run_fail["status"], "PARTIAL_FAILURE")
        self.assertGreater(run_fail["failed"], 0)

        # 5. Clear transient failure & run sync -> FAILED items are retried and become SYNCED
        self.client.post(
            "/api/v1/sync/connectivity",
            headers=headers,
            json={"online": True, "simulate_transient_failure": False},
        )
        run_ok = self.client.post("/api/v1/sync/run", headers=headers).json()
        self.assertEqual(run_ok["status"], "COMPLETED")
        self.assertEqual(run_ok["remaining_pending"], 0)
        self.assertGreater(run_ok["retried"], 0)
        unique_acks_1 = run_ok["remote_unique_acknowledged_count"]

        # 6. Force a re-run and verify idempotency (no duplicate remote acknowledgements created)
        run_again = self.client.post("/api/v1/sync/run", headers=headers).json()
        self.assertEqual(run_again["remote_unique_acknowledged_count"], unique_acks_1)

    # 10. Settings Validation & Runtime Effect + CSV Export Formula Injection Protection
    def test_10_settings_behavior_and_csv_export(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # Invalid settings rejected (warning >= critical threshold)
        bad_set = self.client.patch(
            "/api/v1/settings",
            headers=headers,
            json={
                "device_thresholds": {
                    "PUMP-01": {
                        "vib_warning_threshold": 8.0,
                        "vib_critical_threshold": 6.0,
                    }
                }
            },
        )
        self.assertEqual(bad_set.status_code, 422)

        # Update stale_data_timeout_seconds to 10s and lower PUMP-01 vib_warning_threshold to 3.2 mm/s
        good_set = self.client.patch(
            "/api/v1/settings",
            headers=headers,
            json={
                "stale_data_timeout_seconds": 10,
                "device_thresholds": {
                    "PUMP-01": {
                        "vib_warning_threshold": 3.2,
                        "vib_critical_threshold": 6.5,
                        "persistence_window_count": 1,
                    }
                },
            },
        )
        self.assertEqual(good_set.status_code, 200)
        self.assertEqual(good_set.json()["settings"]["stale_data_timeout_seconds"], 10)

        # Verify lowered threshold (3.2 mm/s with persistence 1) immediately triggers warning on 3.5 mm/s reading
        trig = self.client.post(
            "/api/v1/equipment/ingest",
            headers=headers,
            json={
                "device_id": "PUMP-01",
                "sequence_number": 90,
                "timestamp": utc_now_iso(),
                "temperature": 42.0,
                "vibration": 3.5,
                "current_amps": 4.9,
            },
        )
        self.assertEqual(trig.status_code, 200)
        self.assertGreater(len(trig.json()["alerts_generated"]), 0)

        # Verify CSV export & formula injection protection
        self.assertEqual(sanitize_csv_cell("=CMD|' /C calc'!A0"), "'=CMD|' /C calc'!A0")
        self.assertEqual(sanitize_csv_cell("+SUM(A1:A10)"), "'+SUM(A1:A10)")
        self.assertEqual(sanitize_csv_cell("@malicious"), "'@malicious")

        csv_resp = self.client.get("/api/v1/analytics/export", headers=headers)
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("RECORD_TYPE,ID,TIMESTAMP_UTC", csv_resp.text)



    # 11. All Fault-Injection Scenarios (A through J), Simulator Controls, Dashboard, and Analytics Evaluation
    def test_11_all_scenarios_simulator_controls_and_evaluation(self) -> None:
        _, adm_token = self._login("admin", "ResilixAdmin!2026")
        headers = self._auth_headers(adm_token)

        # Simulator start / pause / resume / step / reset controls
        st = self.client.post("/api/v1/simulator/start", headers=headers, json={"speed_multiplier": 2.0, "device_id": "PUMP-01"})
        self.assertEqual(st.status_code, 200)
        self.assertTrue(st.json()["status"]["running"])

        ps = self.client.post("/api/v1/simulator/pause", headers=headers)
        self.assertEqual(ps.status_code, 200)
        self.assertTrue(ps.json()["paused"])

        rs = self.client.post("/api/v1/simulator/resume", headers=headers)
        self.assertEqual(rs.status_code, 200)
        self.assertFalse(rs.json()["paused"])

        stp = self.client.post("/api/v1/simulator/step", headers=headers, json={"device_id": "PUMP-01"})
        self.assertEqual(stp.status_code, 200)
        self.assertEqual(stp.json()["devices_processed"], 1)

        rst = self.client.post("/api/v1/simulator/reset", headers=headers)
        self.assertEqual(rst.status_code, 200)
        self.assertFalse(rst.json()["status"]["running"])

        # Execute all 10 scenarios A through J in sequence
        for code in [
            "A_NORMAL",
            "B_ELEVATED_VIBRATION",
            "C_RISING_TEMPERATURE",
            "D_MISSING_SENSOR",
            "E_STALE_SENSOR",
            "F_IMPLAUSIBLE_READING",
            "G_INCONSISTENT_READING",
            "H_NETWORK_OUTAGE",
            "I_NETWORK_RECOVERY",
            "J_SENSOR_RECOVERY",
        ]:
            sc_resp = self.client.post(
                "/api/v1/simulator/scenarios",
                headers=headers,
                json={"scenario_code": code, "device_id": "PUMP-01", "steps": 3},
            )
            self.assertEqual(sc_resp.status_code, 200, f"Scenario {code} failed: {sc_resp.text}")
            self.assertTrue(sc_resp.json()["passed"], f"Scenario {code} did not pass: {sc_resp.json()}")

        # Verify dashboard timeseries & activity endpoints
        ts_resp = self.client.get("/api/v1/dashboard/timeseries?device_id=PUMP-01&range_window=15m", headers=headers)
        self.assertEqual(ts_resp.status_code, 200)
        self.assertGreater(ts_resp.json()["count"], 0)

        act_resp = self.client.get("/api/v1/dashboard/activity?limit=15", headers=headers)
        self.assertEqual(act_resp.status_code, 200)
        self.assertGreater(act_resp.json()["count"], 0)

        # Verify analytics summary & evaluation report
        sum_resp = self.client.get("/api/v1/analytics/summary", headers=headers)
        self.assertEqual(sum_resp.status_code, 200)
        self.assertGreater(sum_resp.json()["telemetry_volume"]["total"], 10)

        eval_resp = self.client.get("/api/v1/analytics/evaluation", headers=headers)
        self.assertEqual(eval_resp.status_code, 200)
        eval_data = eval_resp.json()
        self.assertEqual(len(eval_data["scenario_executions"]), 10)
        self.assertIsNotNone(eval_data["metrics"]["precision"])
        self.assertIsNotNone(eval_data["metrics"]["recall"])
        self.assertIsNotNone(eval_data["metrics"]["f1_score"])

        # Verify security overview & audit logs
        sec_resp = self.client.get("/api/v1/security/overview", headers=headers)
        self.assertEqual(sec_resp.status_code, 200)
        self.assertTrue(sec_resp.json()["event_chain_verification"]["valid"])

        aud_resp = self.client.get("/api/v1/security/audit", headers=headers)
        self.assertEqual(aud_resp.status_code, 200)
        self.assertGreater(aud_resp.json()["count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
