"""SQLite metadata store for URT runs/findings/waivers."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from ..constants import SEVERITY_ORDER
from ..types import RunRecord, UnifiedFinding, WaiverRecord


class MetadataStore:
    """Persist URT metadata in sqlite (local/dev default)."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    scorecard_path TEXT,
                    findings_path TEXT,
                    error_message TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    category TEXT NOT NULL,
                    sub_category TEXT,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    attack_vector TEXT NOT NULL,
                    attack_complexity TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    evidence_refs_json TEXT NOT NULL,
                    repro_steps_json TEXT NOT NULL,
                    mappings_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id)
                );

                CREATE TABLE IF NOT EXISTS waivers (
                    waiver_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS waiver_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    waiver_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    at TEXT NOT NULL,
                    expires_at_before TEXT,
                    expires_at_after TEXT,
                    note TEXT
                );
                """
            )

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_run(self, record: RunRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, name, profile, status, created_at, updated_at,
                    scorecard_path, findings_path, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    record.run_id,
                    record.name,
                    record.profile,
                    record.status,
                    record.created_at,
                    record.updated_at,
                    record.scorecard_path,
                    record.findings_path,
                ),
            )

    def update_run(
        self,
        run_id: str,
        *,
        status: str,
        updated_at: str,
        scorecard_path: str | None = None,
        findings_path: str | None = None,
        error_message: str | None = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET status = ?, updated_at = ?,
                    scorecard_path = COALESCE(?, scorecard_path),
                    findings_path = COALESCE(?, findings_path),
                    error_message = COALESCE(?, error_message)
                WHERE run_id = ?
                """,
                (status, updated_at, scorecard_path, findings_path, error_message, run_id),
            )

    def insert_findings(self, findings: Iterable[UnifiedFinding]) -> None:
        rows = []
        for finding in findings:
            rows.append(
                (
                    finding.finding_id,
                    finding.run_id,
                    finding.target_id,
                    finding.engine,
                    finding.category,
                    finding.sub_category,
                    finding.severity,
                    float(finding.confidence),
                    finding.attack_vector,
                    finding.attack_complexity,
                    1 if finding.success else 0,
                    finding.description,
                    json.dumps(finding.evidence_refs, ensure_ascii=False),
                    json.dumps(finding.repro_steps, ensure_ascii=False),
                    json.dumps(finding.mappings, ensure_ascii=False),
                    json.dumps(finding.metadata, ensure_ascii=False),
                )
            )

        if not rows:
            return

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, run_id, target_id, engine, category, sub_category,
                    severity, confidence, attack_vector, attack_complexity,
                    success, description, evidence_refs_json, repro_steps_json,
                    mappings_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def list_runs(self) -> list[dict]:
        with self._connect() as conn:
            data = conn.execute(
                "SELECT run_id, name, profile, status, created_at, updated_at, scorecard_path, findings_path, error_message FROM runs ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in data]

    def get_run(self, run_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT run_id, name, profile, status, created_at, updated_at, scorecard_path, findings_path, error_message FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def get_findings(self, run_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT finding_id, run_id, target_id, engine, category, sub_category,
                       severity, confidence, attack_vector, attack_complexity, success,
                       description, evidence_refs_json, repro_steps_json, mappings_json, metadata_json
                FROM findings
                WHERE run_id = ?
                ORDER BY finding_id ASC
                """,
                (run_id,),
            ).fetchall()

        parsed = []
        for row in rows:
            item = dict(row)
            item["success"] = bool(item["success"])
            item["evidence_refs"] = json.loads(item.pop("evidence_refs_json"))
            item["repro_steps"] = json.loads(item.pop("repro_steps_json"))
            item["mappings"] = json.loads(item.pop("mappings_json"))
            item["metadata"] = json.loads(item.pop("metadata_json"))
            parsed.append(item)
        # Severity is a rank, not a word: sort by SEVERITY_ORDER (stable on finding_id).
        parsed.sort(key=lambda item: -SEVERITY_ORDER.get(str(item["severity"]).lower(), -1))
        return parsed

    def create_waiver(self, waiver: WaiverRecord) -> None:
        payload = asdict(waiver)
        with self._connect() as conn:
            previous = conn.execute(
                "SELECT expires_at FROM waivers WHERE waiver_id = ?", (payload["waiver_id"],)
            ).fetchone()
            conn.execute(
                """
                INSERT OR REPLACE INTO waivers (
                    waiver_id, target_id, control_id, reason, owner, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["waiver_id"],
                    payload["target_id"],
                    payload["control_id"],
                    payload["reason"],
                    payload["owner"],
                    payload["expires_at"],
                ),
            )
            self._record_waiver_event(
                conn,
                waiver_id=payload["waiver_id"],
                event="created" if previous is None else "replaced",
                expires_at_before=None if previous is None else previous["expires_at"],
                expires_at_after=payload["expires_at"],
                note=None,
            )

    def _record_waiver_event(
        self,
        conn: sqlite3.Connection,
        *,
        waiver_id: str,
        event: str,
        expires_at_before: str | None,
        expires_at_after: str | None,
        note: str | None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO waiver_events (waiver_id, event, at, expires_at_before, expires_at_after, note)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (waiver_id, event, self._utc_now(), expires_at_before, expires_at_after, note),
        )

    def get_waiver(self, waiver_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT waiver_id, target_id, control_id, reason, owner, expires_at FROM waivers WHERE waiver_id = ?",
                (waiver_id,),
            ).fetchone()
        return None if row is None else dict(row)

    def update_waiver_expiry(
        self,
        waiver_id: str,
        expires_at: str,
        *,
        event: str = "expiry_changed",
        note: str | None = None,
    ) -> dict | None:
        """Change only `expires_at` (revoke = set it to now) and append an audit event.

        Waivers are never deleted: the row and its history stay readable. Returns the
        updated row, or None when the waiver does not exist.
        """
        with self._connect() as conn:
            current = conn.execute(
                "SELECT expires_at FROM waivers WHERE waiver_id = ?", (waiver_id,)
            ).fetchone()
            if current is None:
                return None
            conn.execute("UPDATE waivers SET expires_at = ? WHERE waiver_id = ?", (expires_at, waiver_id))
            self._record_waiver_event(
                conn,
                waiver_id=waiver_id,
                event=event,
                expires_at_before=current["expires_at"],
                expires_at_after=expires_at,
                note=note,
            )
        return self.get_waiver(waiver_id)

    def list_waiver_events(self, waiver_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, waiver_id, event, at, expires_at_before, expires_at_after, note
                FROM waiver_events WHERE waiver_id = ? ORDER BY event_id ASC
                """,
                (waiver_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_waivers(self, target_id: str | None = None) -> list[dict]:
        with self._connect() as conn:
            if target_id:
                rows = conn.execute(
                    "SELECT waiver_id, target_id, control_id, reason, owner, expires_at FROM waivers WHERE target_id = ? ORDER BY expires_at ASC",
                    (target_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT waiver_id, target_id, control_id, reason, owner, expires_at FROM waivers ORDER BY expires_at ASC"
                ).fetchall()
        return [dict(row) for row in rows]
