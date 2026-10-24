"""
RESILIX Offline-First Event Queue & Synchronization Service
Implements:
- Local SQLite-backed synchronization queue (`sync_queue_items`)
- Simulated remote sink (`sync_acknowledgements` table, explicitly labelled `SIMULATED_REMOTE_SINK_V1`)
- Connectivity toggle (`online` / `offline`) and transient failure simulation
- Deterministic FIFO batch processing with cryptographic event integrity verification before sync
- Stable idempotency keys (`IDEMP-{event_id}-{hash[:16]}`) preventing duplicate remote insertion
- Bounded retries with exponential backoff (`sync_backoff_base_seconds * 2^(attempt-1)`)
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.database import DatabaseSession, utc_now_iso
from app.services.integrity import record_event_with_integrity, verify_single_event_integrity
from app.services.settings_service import get_runtime_settings

_sync_state: dict[str, Any] = {
    "online": True,
    "simulate_transient_failure": False,
    "last_sync_attempt_at": None,
    "last_successful_sync_at": None,
    "last_sync_report": None,
}


def get_sync_connectivity_state() -> dict[str, Any]:
    return dict(_sync_state)


def set_sync_connectivity_state(
    db: DatabaseSession,
    online: bool,
    simulate_transient_failure: bool = False,
    actor_username: str = "admin",
) -> dict[str, Any]:
    prev_online = _sync_state["online"]
    _sync_state["online"] = bool(online)
    _sync_state["simulate_transient_failure"] = bool(simulate_transient_failure)

    now_iso = utc_now_iso()
    if prev_online != online:
        state_label = "ONLINE" if online else "OFFLINE"
        record_event_with_integrity(
            db=db,
            device_id=None,
            metric="sync_link",
            event_category="SYNCHRONIZATION",
            event_type=f"SYNC_LINK_{state_label}",
            severity="INFO" if online else "WARNING",
            rule_id=f"RULE_SYNC_LINK_{state_label}",
            summary=f"Remote synchronization link set to {state_label} by {actor_username}",
            explanation=(
                f"Simulated remote synchronization adapter transitioned from "
                f"{'ONLINE' if prev_online else 'OFFLINE'} to {state_label}. "
                + (
                    "Local telemetry monitoring, anomaly detection, and append-only event queueing continue locally."
                    if not online
                    else "Queued local events are now eligible for deterministic synchronization."
                )
            ),
            recommended_action=(
                "Events will queue locally in SQLite until connectivity is restored."
                if not online
                else "Trigger synchronization to flush pending local events to the simulated remote sink."
            ),
            event_source="SYNC_CONTROLLER",
            enqueue_for_sync=True,
        )
    return get_sync_status_summary(db)


def get_sync_status_summary(db: DatabaseSession) -> dict[str, Any]:
    counts_rows = db.fetchall(
        "SELECT sync_state, COUNT(*) AS cnt FROM sync_queue_items GROUP BY sync_state"
    )
    counts = {"PENDING": 0, "SYNCING": 0, "SYNCED": 0, "FAILED": 0}
    for r in counts_rows:
        counts[r["sync_state"]] = int(r["cnt"])

    remote_ack_count_row = db.fetchone("SELECT COUNT(*) AS cnt FROM sync_acknowledgements")
    remote_ack_count = int(remote_ack_count_row["cnt"]) if remote_ack_count_row else 0

    retried_row = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM sync_queue_items WHERE attempt_count > 1"
    )
    retried_count = int(retried_row["cnt"]) if retried_row else 0

    last_synced_row = db.fetchone(
        "SELECT MAX(synced_at) AS max_ts FROM sync_queue_items WHERE sync_state = 'SYNCED'"
    )
    last_synced_at = (
        last_synced_row["max_ts"]
        if (last_synced_row and last_synced_row["max_ts"])
        else _sync_state["last_successful_sync_at"]
    )

    return {
        "online": _sync_state["online"],
        "simulate_transient_failure": _sync_state["simulate_transient_failure"],
        "remote_adapter_label": "SIMULATED_REMOTE_SINK_V1 (Local SQLite Sink — No External Cloud Required)",
        "pending_count": counts["PENDING"],
        "syncing_count": counts["SYNCING"],
        "synced_count": counts["SYNCED"],
        "failed_count": counts["FAILED"],
        "retried_items_count": retried_count,
        "remote_unique_acknowledged_count": remote_ack_count,
        "last_sync_attempt_at": _sync_state["last_sync_attempt_at"],
        "last_successful_sync_at": last_synced_at,
        "last_sync_report": _sync_state["last_sync_report"],
        "edge_resilience_note": (
            "Offline resilience operates at the local RESILIX edge service & SQLite storage layer. "
            "While the remote link is offline, the local process continues ingesting telemetry, "
            "detecting anomalies, and chaining events locally."
        ),
    }


def run_synchronization_batch(
    db: DatabaseSession,
    batch_limit: int = 100,
    ignore_backoff_for_manual_run: bool = True,
) -> dict[str, Any]:
    """
    Synchronize pending and retry-eligible failed events in deterministic order.
    Guarantees idempotency via `idempotency_key` on `sync_acknowledgements`.
    """
    now_iso = utc_now_iso()
    _sync_state["last_sync_attempt_at"] = now_iso
    runtime_cfg = get_runtime_settings(db)
    max_retries = int(runtime_cfg.get("sync_max_retries", 5))
    backoff_base = float(runtime_cfg.get("sync_backoff_base_seconds", 2.0))

    if not _sync_state["online"]:
        report = {
            "status": "OFFLINE_SKIPPED",
            "online": False,
            "processed": 0,
            "synced_newly": 0,
            "deduplicated_skips": 0,
            "failed": 0,
            "retried": 0,
            "timestamp": now_iso,
            "message": "Synchronization link is currently OFFLINE. Events remain safely queued in SQLite.",
        }
        _sync_state["last_sync_report"] = report
        return report

    items = db.fetchall(
        """
        SELECT * FROM sync_queue_items
        WHERE sync_state IN ('PENDING', 'FAILED') AND attempt_count < ?
        ORDER BY created_at ASC, queue_id ASC
        LIMIT ?
        """,
        (max_retries, batch_limit),
    )

    processed = 0
    synced_newly = 0
    deduplicated_skips = 0
    failed = 0
    retried = 0

    for item in items:
        if not ignore_backoff_for_manual_run and item["next_retry_at"]:
            if item["next_retry_at"] > now_iso:
                continue

        processed += 1
        q_id = item["queue_id"]
        evt_id = item["event_id"]
        idemp_key = item["idempotency_key"]
        attempt = int(item["attempt_count"]) + 1
        if attempt > 1:
            retried += 1

        # Mark SYNCING
        db.execute(
            "UPDATE sync_queue_items SET sync_state = 'SYNCING', attempt_count = ?, last_attempt_at = ? WHERE queue_id = ?",
            (attempt, now_iso, q_id),
        )

        # Simulate transient network error if requested
        if _sync_state["simulate_transient_failure"]:
            backoff_sec = backoff_base * (2 ** (attempt - 1))
            next_retry_dt = datetime.now(timezone.utc) + timedelta(seconds=backoff_sec)
            next_retry_iso = next_retry_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            db.execute(
                """
                UPDATE sync_queue_items SET
                    sync_state = 'FAILED',
                    last_error = 'Simulated transient remote gateway timeout (HTTP 503)',
                    next_retry_at = ?
                WHERE queue_id = ?
                """,
                (next_retry_iso, q_id),
            )
            failed += 1
            continue

        # Verify event cryptographic integrity before sending to remote sink
        verification = verify_single_event_integrity(db, evt_id)
        if not verification.get("valid", False):
            db.execute(
                """
                UPDATE sync_queue_items SET
                    sync_state = 'FAILED',
                    last_error = 'Integrity verification failed prior to synchronization; event quarantined.'
                WHERE queue_id = ?
                """,
                (q_id,),
            )
            failed += 1
            continue

        # Check idempotency in simulated remote sink
        existing_ack = db.fetchone(
            "SELECT * FROM sync_acknowledgements WHERE idempotency_key = ? OR event_id = ?",
            (idemp_key, evt_id),
        )
        if existing_ack:
            deduplicated_skips += 1
            ack_id = existing_ack["ack_id"]
        else:
            ack_id = f"ACK-{secrets.token_hex(5).upper()}"
            db.execute(
                """
                INSERT INTO sync_acknowledgements (
                    ack_id, idempotency_key, event_id, device_id,
                    event_hash, verified_integrity, remote_sink_label, received_at
                ) VALUES (?, ?, ?, ?, ?, 1, 'SIMULATED_REMOTE_SINK_V1', ?)
                """,
                (
                    ack_id,
                    idemp_key,
                    evt_id,
                    item["device_id"],
                    item["event_hash"],
                    now_iso,
                ),
            )
            synced_newly += 1

        db.execute(
            """
            UPDATE sync_queue_items SET
                sync_state = 'SYNCED',
                ack_id = ?,
                synced_at = ?,
                last_error = NULL,
                next_retry_at = NULL
            WHERE queue_id = ?
            """,
            (ack_id, now_iso, q_id),
        )

    if synced_newly > 0 or deduplicated_skips > 0:
        _sync_state["last_successful_sync_at"] = now_iso

    summary = get_sync_status_summary(db)
    report = {
        "status": "COMPLETED" if failed == 0 else "PARTIAL_FAILURE",
        "online": True,
        "processed": processed,
        "synced_newly": synced_newly,
        "deduplicated_skips": deduplicated_skips,
        "failed": failed,
        "retried": retried,
        "remaining_pending": summary["pending_count"],
        "total_synced": summary["synced_count"],
        "remote_unique_acknowledged_count": summary["remote_unique_acknowledged_count"],
        "timestamp": now_iso,
        "message": (
            f"Processed {processed} queued item(s): {synced_newly} newly synchronized, "
            f"{deduplicated_skips} deduplicated via idempotency key, {failed} failed."
        ),
    }
    _sync_state["last_sync_report"] = report
    return report
