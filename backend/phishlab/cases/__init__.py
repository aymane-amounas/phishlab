"""SQLite case persistence. Parameterized queries only. Evidence kept separate from
analyst-added conclusions (notes/disposition/rationale)."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from phishlab.config import settings

DISPOSITIONS = {"undetermined", "benign", "suspicious", "malicious", "inconclusive"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id               TEXT PRIMARY KEY,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    artifact_sha256  TEXT NOT NULL,
    source_kind      TEXT NOT NULL,
    declared_filename TEXT,
    subject          TEXT,
    sender           TEXT,
    highest_severity TEXT NOT NULL,
    finding_count    INTEGER NOT NULL DEFAULT 0,
    disposition      TEXT NOT NULL DEFAULT 'undetermined',
    rationale        TEXT,
    notes            TEXT,
    analysis_json    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_created  ON cases(created_at);
CREATE INDEX IF NOT EXISTS idx_cases_sha      ON cases(artifact_sha256);
CREATE INDEX IF NOT EXISTS idx_cases_disp     ON cases(disposition);
CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(highest_severity);
"""


@dataclass
class CaseSummary:
    id: str
    created_at: str
    subject: str | None
    sender: str | None
    highest_severity: str
    finding_count: int
    disposition: str


def _now() -> str:
    return datetime.now(UTC).isoformat()


class CaseStore:
    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or settings.db_path
        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def create(self, analysis: dict) -> str:
        cid = str(uuid.uuid4())
        now = _now()
        art = analysis.get("artifact", {})
        sh = analysis.get("summary_headers", {})
        assess = analysis.get("assessment", {})
        self._conn.execute(
            """INSERT INTO cases (id, created_at, updated_at, artifact_sha256, source_kind,
               declared_filename, subject, sender, highest_severity, finding_count,
               analysis_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cid,
                now,
                now,
                art.get("sha256", ""),
                art.get("source_kind", ""),
                art.get("declared_filename"),
                sh.get("subject"),
                sh.get("from"),
                assess.get("highest_severity", "informational"),
                len(analysis.get("findings", [])),
                json.dumps(analysis),
            ),
        )
        self._conn.commit()
        return cid

    def get(self, cid: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM cases WHERE id = ?", (cid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["analysis"] = json.loads(d.pop("analysis_json"))
        return d

    def update_disposition(self, cid: str, disposition: str, rationale: str | None) -> bool:
        if disposition not in DISPOSITIONS:
            raise ValueError(f"Invalid disposition: {disposition!r}")
        cur = self._conn.execute(
            "UPDATE cases SET disposition=?, rationale=?, updated_at=? WHERE id=?",
            (disposition, rationale, _now(), cid),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def update_notes(self, cid: str, notes: str) -> bool:
        cur = self._conn.execute(
            "UPDATE cases SET notes=?, updated_at=? WHERE id=?", (notes, _now(), cid)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def delete(self, cid: str) -> bool:
        cur = self._conn.execute("DELETE FROM cases WHERE id=?", (cid,))
        self._conn.commit()
        return cur.rowcount > 0

    def list(
        self,
        q: str | None = None,
        disposition: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CaseSummary]:
        sql = "SELECT id, created_at, subject, sender, highest_severity, finding_count, disposition FROM cases"
        clauses: list[str] = []
        params: list = []
        if q:
            clauses.append("(subject LIKE ? OR sender LIKE ? OR artifact_sha256 LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like]
        if disposition:
            clauses.append("disposition = ?")
            params.append(disposition)
        if severity:
            clauses.append("highest_severity = ?")
            params.append(severity)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = self._conn.execute(sql, params).fetchall()
        return [CaseSummary(**dict(r)) for r in rows]

    def stats(self) -> dict:
        total = self._conn.execute("SELECT COUNT(*) AS c FROM cases").fetchone()["c"]
        by_sev = {
            r["highest_severity"]: r["c"]
            for r in self._conn.execute(
                "SELECT highest_severity, COUNT(*) AS c FROM cases GROUP BY highest_severity"
            ).fetchall()
        }
        by_disp = {
            r["disposition"]: r["c"]
            for r in self._conn.execute(
                "SELECT disposition, COUNT(*) AS c FROM cases GROUP BY disposition"
            ).fetchall()
        }
        return {"total": total, "by_severity": by_sev, "by_disposition": by_disp}

    def purge_older_than(self, days: int) -> int:
        """Retention control: delete cases older than `days`. Returns count removed."""
        if days <= 0:
            return 0
        cutoff = datetime.now(UTC).timestamp() - days * 86400
        cutoff_iso = datetime.fromtimestamp(cutoff, tz=UTC).isoformat()
        cur = self._conn.execute("DELETE FROM cases WHERE created_at < ?", (cutoff_iso,))
        self._conn.commit()
        return cur.rowcount
