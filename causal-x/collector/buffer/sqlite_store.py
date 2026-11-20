from datetime import datetime, timedelta, timezone
import json
import os
import sqlite3
from typing import Any, Dict, List


class SQLiteCollectorStore:
    """
    Tier 1 local SQLite persistence:
    - raw_events: Raw local telemetry & secrets (NEVER transmitted centrally).
    - egress_proofs_local: Cryptographic proof log created BEFORE sending.
    - outbox_queue: Durable retry buffer with exponential backoff.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        parent = os.path.dirname(os.path.abspath(db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS raw_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    captured_at_utc TEXT NOT NULL,
                    raw_payload_json TEXT NOT NULL,
                    raw_risk_score INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS egress_proofs_local (
                    payload_id TEXT PRIMARY KEY,
                    created_at_utc TEXT NOT NULL,
                    approval_decision TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    payload_hash_sha256 TEXT NOT NULL,
                    hmac_signature TEXT NOT NULL,
                    blocked_fields_json TEXT NOT NULL,
                    allowed_fields_json TEXT NOT NULL,
                    approved_metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS outbox_queue (
                    payload_id TEXT PRIMARY KEY,
                    envelope_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    next_retry_utc TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    delivered_at_utc TEXT
                );
                """
            )

    def save_raw_event(self, event_id: str, raw_record: Dict[str, Any], raw_risk_score: int) -> None:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO raw_events (event_id, captured_at_utc, raw_payload_json, raw_risk_score)
                VALUES (?, ?, ?, ?)
                """,
                (event_id, now_utc, json.dumps(raw_record, sort_keys=True), raw_risk_score),
            )

    def save_local_proof_and_enqueue(self, envelope: Dict[str, Any]) -> None:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO egress_proofs_local (
                    payload_id, created_at_utc, approval_decision, policy_version,
                    payload_hash_sha256, hmac_signature, blocked_fields_json,
                    allowed_fields_json, approved_metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope["payload_id"],
                    envelope["created_at_utc"],
                    envelope["approval_decision"],
                    envelope["policy_version"],
                    envelope["payload_hash_sha256"],
                    envelope["hmac_signature"],
                    json.dumps(envelope["blocked_fields"]),
                    json.dumps(envelope["allowed_fields"]),
                    json.dumps(envelope["approved_metadata"], sort_keys=True),
                ),
            )
            if envelope["approval_decision"] == "APPROVED":
                conn.execute(
                    """
                    INSERT OR IGNORE INTO outbox_queue (
                        payload_id, envelope_json, status, retry_count, next_retry_utc, created_at_utc
                    ) VALUES (?, ?, 'PENDING', 0, ?, ?)
                    """,
                    (
                        envelope["payload_id"],
                        json.dumps(envelope, sort_keys=True),
                        now_utc,
                        now_utc,
                    ),
                )

    def get_due_outbox_items(self, limit: int = 50) -> List[Dict[str, Any]]:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload_id, envelope_json, retry_count
                FROM outbox_queue
                WHERE status = 'PENDING' AND next_retry_utc <= ?
                ORDER BY created_at_utc ASC
                LIMIT ?
                """,
                (now_utc, limit),
            ).fetchall()
        return [
            {
                "payload_id": row["payload_id"],
                "envelope": json.loads(row["envelope_json"]),
                "retry_count": int(row["retry_count"]),
            }
            for row in rows
        ]

    def mark_delivered(self, payload_id: str) -> None:
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE outbox_queue
                SET status = 'DELIVERED', delivered_at_utc = ?
                WHERE payload_id = ?
                """,
                (now_utc, payload_id),
            )

    def schedule_retry(self, payload_id: str, current_retry_count: int) -> str:
        next_retry = current_retry_count + 1
        backoff_seconds = min(60, 2**next_retry)
        next_retry_time = (
            datetime.now(timezone.utc) + timedelta(seconds=backoff_seconds)
        ).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE outbox_queue
                SET retry_count = ?, next_retry_utc = ?
                WHERE payload_id = ?
                """,
                (next_retry, next_retry_time, payload_id),
            )
        return next_retry_time

    def count_pending(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM outbox_queue WHERE status = 'PENDING'"
            ).fetchone()
        return int(row["cnt"]) if row else 0

    def count_delivered(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM outbox_queue WHERE status = 'DELIVERED'"
            ).fetchone()
        return int(row["cnt"]) if row else 0

    def list_raw_events(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_id, captured_at_utc, raw_payload_json, raw_risk_score FROM raw_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "captured_at_utc": row["captured_at_utc"],
                "raw_payload": json.loads(row["raw_payload_json"]),
                "raw_risk_score": row["raw_risk_score"],
            }
            for row in rows
        ]
