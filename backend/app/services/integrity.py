"""
RESILIX Event Integrity & Append-Only Hash Chain Service
Implements:
- Canonical JSON serialization of event records
- SHA-256 append-only hash chain anchored at GENESIS_HASH (64 zeros)
- Per-event and full-chain cryptographic hash verification
- Detection of payload tampering, hash tampering, previous-hash mismatch, or sequence gaps
- Local event creation coupled with offline queue insertion
"""
import hashlib
import json
import secrets
from typing import Any, Optional

from app.config import settings
from app.database import DatabaseSession, utc_now_iso


def build_canonical_event_payload(
    event_id: str,
    sequence_index: int,
    device_id: Optional[str],
    metric: str,
    event_category: str,
    event_type: str,
    severity: str,
    timestamp: str,
    observed_value: Optional[float],
    threshold_value: Optional[float],
    rule_id: str,
    summary: str,
) -> str:
    """Create deterministic, canonical JSON string for SHA-256 chain hashing."""
    canonical_dict = {
        "device_id": device_id or "SYSTEM",
        "event_category": event_category,
        "event_id": event_id,
        "event_type": event_type,
        "metric": metric,
        "observed_value": round(float(observed_value), 4) if observed_value is not None else None,
        "rule_id": rule_id,
        "sequence_index": int(sequence_index),
        "severity": severity,
        "summary": summary,
        "threshold_value": round(float(threshold_value), 4) if threshold_value is not None else None,
        "timestamp": timestamp,
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))


def compute_chain_hash(previous_hash: str, canonical_payload: str) -> str:
    """Compute SHA-256 over previous_hash || '|' || canonical_payload."""
    material = f"{previous_hash}|{canonical_payload}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def record_event_with_integrity(
    db: DatabaseSession,
    device_id: Optional[str],
    metric: str,
    event_category: str,
    event_type: str,
    severity: str,
    rule_id: str,
    summary: str,
    explanation: str,
    recommended_action: str,
    observed_value: Optional[float] = None,
    baseline_value: Optional[float] = None,
    threshold_value: Optional[float] = None,
    deviation_score: Optional[float] = None,
    persistence_count: int = 1,
    event_source: str = "SIMULATOR_BACKEND",
    extra_payload: Optional[dict[str, Any]] = None,
    timestamp: Optional[str] = None,
    enqueue_for_sync: bool = True,
) -> dict[str, Any]:
    """
    Persist an event, append its SHA-256 hash chain record, and optionally enqueue it
    in the local offline-first synchronization queue.
    """
    now_iso = timestamp or utc_now_iso()

    # Determine next sequence index and previous hash
    last_integrity = db.fetchone(
        "SELECT chain_index, event_hash FROM event_integrity_records ORDER BY chain_index DESC LIMIT 1"
    )
    if last_integrity:
        next_index = int(last_integrity["chain_index"]) + 1
        prev_hash = str(last_integrity["event_hash"])
    else:
        next_index = 1
        prev_hash = settings.genesis_hash

    event_id = f"EVT-{next_index:05d}-{secrets.token_hex(3).upper()}"
    canonical_str = build_canonical_event_payload(
        event_id=event_id,
        sequence_index=next_index,
        device_id=device_id,
        metric=metric,
        event_category=event_category,
        event_type=event_type,
        severity=severity,
        timestamp=now_iso,
        observed_value=observed_value,
        threshold_value=threshold_value,
        rule_id=rule_id,
        summary=summary,
    )
    event_hash = compute_chain_hash(prev_hash, canonical_str)

    full_payload = {
        "event_id": event_id,
        "sequence_index": next_index,
        "device_id": device_id,
        "metric": metric,
        "event_category": event_category,
        "event_type": event_type,
        "severity": severity,
        "timestamp": now_iso,
        "observed_value": observed_value,
        "baseline_value": baseline_value,
        "threshold_value": threshold_value,
        "deviation_score": deviation_score,
        "persistence_count": persistence_count,
        "rule_id": rule_id,
        "summary": summary,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "event_source": event_source,
        "extra": extra_payload or {},
    }

    db.execute(
        """
        INSERT INTO events (
            event_id, sequence_index, device_id, metric, event_category,
            event_type, severity, timestamp, observed_value, baseline_value,
            threshold_value, deviation_score, persistence_count, rule_id,
            summary, explanation, recommended_action, event_source,
            acknowledged, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (
            event_id,
            next_index,
            device_id,
            metric,
            event_category,
            event_type,
            severity,
            now_iso,
            observed_value,
            baseline_value,
            threshold_value,
            deviation_score,
            persistence_count,
            rule_id,
            summary,
            explanation,
            recommended_action,
            event_source,
            json.dumps(full_payload, sort_keys=True),
            now_iso,
        ),
    )

    db.execute(
        """
        INSERT INTO event_integrity_records (
            event_id, chain_index, canonical_payload, previous_hash,
            event_hash, hash_algorithm, created_at
        ) VALUES (?, ?, ?, ?, ?, 'SHA-256', ?)
        """,
        (event_id, next_index, canonical_str, prev_hash, event_hash, now_iso),
    )

    queue_id = None
    if enqueue_for_sync:
        queue_id = f"SYNCQ-{next_index:05d}"
        idempotency_key = f"IDEMP-{event_id}-{event_hash[:16]}"
        db.execute(
            """
            INSERT INTO sync_queue_items (
                queue_id, event_id, device_id, idempotency_key,
                payload_json, event_hash, previous_hash, sync_state,
                attempt_count, max_attempts, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, 5, ?)
            """,
            (
                queue_id,
                event_id,
                device_id,
                idempotency_key,
                json.dumps(full_payload, sort_keys=True),
                event_hash,
                prev_hash,
                now_iso,
            ),
        )

    return {
        "event_id": event_id,
        "sequence_index": next_index,
        "previous_hash": prev_hash,
        "event_hash": event_hash,
        "queue_id": queue_id,
        "timestamp": now_iso,
        "rule_id": rule_id,
        "event_type": event_type,
        "severity": severity,
        "summary": summary,
    }


def verify_single_event_integrity(db: DatabaseSession, event_id: str) -> dict[str, Any]:
    """Verify a specific event against its stored integrity record and preceding chain link."""
    evt = db.fetchone("SELECT * FROM events WHERE event_id = ?", (event_id,))
    if not evt:
        return {"valid": False, "event_id": event_id, "error": "Event not found"}

    rec = db.fetchone("SELECT * FROM event_integrity_records WHERE event_id = ?", (event_id,))
    if not rec:
        return {
            "valid": False,
            "event_id": event_id,
            "error": "Missing integrity chain record for event",
        }

    recomputed_canonical = build_canonical_event_payload(
        event_id=evt["event_id"],
        sequence_index=evt["sequence_index"],
        device_id=evt["device_id"],
        metric=evt["metric"],
        event_category=evt["event_category"],
        event_type=evt["event_type"],
        severity=evt["severity"],
        timestamp=evt["timestamp"],
        observed_value=evt["observed_value"],
        threshold_value=evt["threshold_value"],
        rule_id=evt["rule_id"],
        summary=evt["summary"],
    )

    recomputed_hash = compute_chain_hash(rec["previous_hash"], recomputed_canonical)
    payload_matches = recomputed_canonical == rec["canonical_payload"]
    hash_matches = recomputed_hash == rec["event_hash"]

    # Check previous link
    chain_idx = int(rec["chain_index"])
    if chain_idx == 1:
        prev_link_valid = rec["previous_hash"] == settings.genesis_hash
        expected_prev_hash = settings.genesis_hash
    else:
        prev_rec = db.fetchone(
            "SELECT event_hash FROM event_integrity_records WHERE chain_index = ?",
            (chain_idx - 1,),
        )
        expected_prev_hash = prev_rec["event_hash"] if prev_rec else "MISSING_PREDECESSOR"
        prev_link_valid = prev_rec is not None and rec["previous_hash"] == prev_rec["event_hash"]

    is_valid = bool(payload_matches and hash_matches and prev_link_valid)
    return {
        "valid": is_valid,
        "event_id": event_id,
        "chain_index": chain_idx,
        "hash_algorithm": rec["hash_algorithm"],
        "stored_event_hash": rec["event_hash"],
        "recomputed_event_hash": recomputed_hash,
        "stored_previous_hash": rec["previous_hash"],
        "expected_previous_hash": expected_prev_hash,
        "payload_matches_canonical": payload_matches,
        "hash_matches": hash_matches,
        "previous_link_valid": prev_link_valid,
        "verified_at": utc_now_iso(),
    }


def verify_entire_event_chain(db: DatabaseSession) -> dict[str, Any]:
    """
    Walk the entire append-only event chain from genesis and verify:
    1. Sequence continuity (1..N with no missing links)
    2. Canonical payload matches live event table columns
    3. Recomputed SHA-256 hash matches stored event_hash
    4. Each record's previous_hash matches the preceding record's event_hash
    """
    events = db.fetchall("SELECT * FROM events ORDER BY sequence_index ASC")
    records = db.fetchall("SELECT * FROM event_integrity_records ORDER BY chain_index ASC")

    rec_by_event_id = {r["event_id"]: r for r in records}
    mismatches: list[dict[str, Any]] = []
    expected_prev_hash = settings.genesis_hash
    expected_seq = 1

    if len(events) != len(records):
        mismatches.append(
            {
                "issue": "RECORD_COUNT_MISMATCH",
                "events_count": len(events),
                "integrity_records_count": len(records),
                "detail": "Number of events does not match number of integrity chain records.",
            }
        )

    for evt in events:
        seq = int(evt["sequence_index"])
        eid = evt["event_id"]

        if seq != expected_seq:
            mismatches.append(
                {
                    "event_id": eid,
                    "chain_index": seq,
                    "issue": "SEQUENCE_DISCONTINUITY",
                    "detail": f"Expected sequence_index {expected_seq}, found {seq}",
                }
            )
            expected_seq = seq

        rec = rec_by_event_id.get(eid)
        if not rec:
            mismatches.append(
                {
                    "event_id": eid,
                    "chain_index": seq,
                    "issue": "MISSING_INTEGRITY_RECORD",
                    "detail": f"Event {eid} has no corresponding hash-chain entry.",
                }
            )
            expected_seq += 1
            continue

        recomputed_canonical = build_canonical_event_payload(
            event_id=evt["event_id"],
            sequence_index=evt["sequence_index"],
            device_id=evt["device_id"],
            metric=evt["metric"],
            event_category=evt["event_category"],
            event_type=evt["event_type"],
            severity=evt["severity"],
            timestamp=evt["timestamp"],
            observed_value=evt["observed_value"],
            threshold_value=evt["threshold_value"],
            rule_id=evt["rule_id"],
            summary=evt["summary"],
        )

        if recomputed_canonical != rec["canonical_payload"]:
            mismatches.append(
                {
                    "event_id": eid,
                    "chain_index": seq,
                    "issue": "EVENT_PAYLOAD_TAMPERED",
                    "detail": f"Event {eid} database fields differ from signed canonical payload.",
                }
            )

        if rec["previous_hash"] != expected_prev_hash:
            mismatches.append(
                {
                    "event_id": eid,
                    "chain_index": seq,
                    "issue": "BROKEN_PREVIOUS_HASH_LINK",
                    "detail": (
                        f"Event {eid} previous_hash ({rec['previous_hash'][:12]}...) "
                        f"does not match predecessor hash ({expected_prev_hash[:12]}...)."
                    ),
                }
            )

        recomputed_hash = compute_chain_hash(expected_prev_hash, recomputed_canonical)
        if recomputed_hash != rec["event_hash"]:
            mismatches.append(
                {
                    "event_id": eid,
                    "chain_index": seq,
                    "issue": "HASH_MISMATCH",
                    "detail": (
                        f"Recomputed SHA-256 ({recomputed_hash[:12]}...) does not match "
                        f"stored event_hash ({rec['event_hash'][:12]}...)."
                    ),
                }
            )

        expected_prev_hash = rec["event_hash"]
        expected_seq += 1

    status_str = "VERIFIED_INTACT" if len(mismatches) == 0 else "INTEGRITY_COMPROMISED"
    head_hash = records[-1]["event_hash"] if records else settings.genesis_hash

    return {
        "valid": len(mismatches) == 0,
        "status": status_str,
        "total_events_checked": len(events),
        "total_chain_links": len(records),
        "genesis_hash": settings.genesis_hash,
        "head_hash": head_hash,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "verified_at": utc_now_iso(),
        "architectural_note": (
            "Append-only SHA-256 hash chain detects accidental corruption or single-row modification. "
            "Note: A local hash chain alone cannot prevent an attacker with full local database write access "
            "from recomputing the entire chain unless anchored to an external hardware security module (TPM) or remote transparency log."
        ),
    }
