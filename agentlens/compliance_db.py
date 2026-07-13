"""
AgentLens Compliance Database
--------------------------------
Cross-session SQLite store for override rate tracking, rubber-stamp
detection, and accountability chain reporting.

No external dependencies — uses Python stdlib sqlite3.

Why this matters:
  US SR 26-2 "effective challenge": requires evidence that human reviewers
  are genuinely engaging with AI recommendations, not just rubber-stamping.
  Override rate is the proxy metric. A rate of 0.0 across many sessions
  is a strong signal that the human-in-the-loop is not functioning.

  UK ICO: controller/processor distinction must be documented.
  Singapore MGF Dimension 2: human accountability at both individual
  and organisational level must be tracked.

Usage:
    db = ComplianceDatabase()   # defaults to ~/.agentlens/compliance.db
    db.record_session(session_summary)

    print(db.override_rate("MyBank Ltd."))   # 0.08 → 8% override rate
    print(db.rubber_stamp_sessions("MyBank Ltd."))  # sessions with 0 overrides
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


_DEFAULT_DB_PATH = Path.home() / ".agentlens" / "compliance.db"


class ComplianceDatabase:
    """
    Lightweight SQLite store for cross-session compliance metrics.

    Thread-safe. Each call acquires its own connection to avoid
    cross-thread SQLite issues.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id      TEXT PRIMARY KEY,
                    entity_name     TEXT NOT NULL,
                    session_purpose TEXT,
                    recorded_at_utc TEXT NOT NULL,
                    total_decisions INTEGER NOT NULL DEFAULT 0,
                    human_overrides INTEGER NOT NULL DEFAULT 0,
                    guardrails_triggered INTEGER NOT NULL DEFAULT 0,
                    chain_intact    INTEGER NOT NULL DEFAULT 1,
                    risk_tier_min   INTEGER,
                    framework_json  TEXT
                );

                CREATE TABLE IF NOT EXISTS responsibility_map (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_name     TEXT NOT NULL,
                    role            TEXT NOT NULL,
                    party_name      TEXT NOT NULL,
                    party_ref       TEXT,
                    recorded_at_utc TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_entity
                    ON sessions(entity_name);
                CREATE INDEX IF NOT EXISTS idx_sessions_recorded
                    ON sessions(recorded_at_utc);
            """)
            conn.commit()
            conn.close()

    # ── Session recording ────────────────────────────────────────────────────

    def record_session(self, summary: Dict[str, Any]) -> None:
        """
        Record a session summary produced by AuditLog.summary() or
        ChatSessionTracer.get_session_summary().

        Idempotent — re-recording the same session_id updates the record.
        """
        with self._lock:
            conn = self._connect()
            conn.execute("""
                INSERT INTO sessions
                    (session_id, entity_name, session_purpose, recorded_at_utc,
                     total_decisions, human_overrides, guardrails_triggered,
                     chain_intact, risk_tier_min, framework_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    total_decisions     = excluded.total_decisions,
                    human_overrides     = excluded.human_overrides,
                    guardrails_triggered = excluded.guardrails_triggered,
                    chain_intact        = excluded.chain_intact
            """, (
                summary.get("session_id", "unknown"),
                summary.get("entity", summary.get("entity_name", "unknown")),
                summary.get("session_purpose", ""),
                datetime.now(timezone.utc).isoformat(),
                summary.get("decisions_recorded", summary.get("total_turns", 0)),
                summary.get("human_overrides", 0),
                summary.get("guardrails_triggered", 0),
                int(summary.get("chain_intact", True)),
                summary.get("min_risk_tier"),
                json.dumps(summary.get("frameworks", [])),
            ))
            conn.commit()
            conn.close()

    # ── Override rate ────────────────────────────────────────────────────────

    def override_rate(
        self,
        entity_name: str,
        last_n_sessions: Optional[int] = None,
    ) -> float:
        """
        Compute override rate = human_overrides / total_decisions
        across all (or the last N) sessions for an entity.

        Returns 0.0 if no decisions have been recorded.
        """
        with self._lock:
            conn = self._connect()
            if last_n_sessions:
                rows = conn.execute("""
                    SELECT total_decisions, human_overrides
                    FROM sessions
                    WHERE entity_name = ?
                    ORDER BY recorded_at_utc DESC
                    LIMIT ?
                """, (entity_name, last_n_sessions)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT total_decisions, human_overrides
                    FROM sessions
                    WHERE entity_name = ?
                """, (entity_name,)).fetchall()
            conn.close()

        total_decisions = sum(r["total_decisions"] for r in rows)
        total_overrides = sum(r["human_overrides"] for r in rows)

        if total_decisions == 0:
            return 0.0
        return round(total_overrides / total_decisions, 4)

    # ── Rubber-stamp detection ───────────────────────────────────────────────

    def rubber_stamp_sessions(
        self,
        entity_name: str,
        min_decisions: int = 5,
        last_n_sessions: Optional[int] = None,
    ) -> List[str]:
        """
        Return session IDs where human_overrides == 0 and
        total_decisions >= min_decisions.

        A pattern of zero overrides across many decisions is a strong signal
        that the human reviewer is rubber-stamping AI decisions without
        genuine engagement. Flagged by US SR 26-2 'effective challenge' audit.

        Args:
            min_decisions: only flag sessions with at least this many decisions
                           (avoid flagging sessions with a single, trivial decision)
        """
        with self._lock:
            conn = self._connect()
            query = """
                SELECT session_id
                FROM sessions
                WHERE entity_name = ?
                  AND human_overrides = 0
                  AND total_decisions >= ?
                ORDER BY recorded_at_utc DESC
            """
            params = [entity_name, min_decisions]
            if last_n_sessions:
                query += " LIMIT ?"
                params.append(last_n_sessions)

            rows = conn.execute(query, params).fetchall()
            conn.close()

        return [r["session_id"] for r in rows]

    # ── Responsibility map ───────────────────────────────────────────────────

    def set_responsibility_map(
        self,
        entity_name: str,
        developer: str,
        platform: str,
        deployer: str,
        end_user_ref: str = "",
        party_refs: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Record the developer → platform → deployer → user responsibility chain.
        Required by UK ICO (controller/processor distinction) and
        Singapore MGF Dimension 2 (organisational accountability).
        """
        refs = party_refs or {}
        roles = [
            ("developer", developer, refs.get("developer", "")),
            ("platform",  platform,  refs.get("platform", "")),
            ("deployer",  deployer,  refs.get("deployer", "")),
            ("end_user",  end_user_ref, refs.get("end_user", "")),
        ]
        with self._lock:
            conn = self._connect()
            now = datetime.now(timezone.utc).isoformat()
            for role, party_name, party_ref in roles:
                if not party_name:
                    continue
                conn.execute("""
                    INSERT INTO responsibility_map
                        (entity_name, role, party_name, party_ref, recorded_at_utc)
                    VALUES (?, ?, ?, ?, ?)
                """, (entity_name, role, party_name, party_ref, now))
            conn.commit()
            conn.close()

    def get_responsibility_map(self, entity_name: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute("""
                SELECT role, party_name, party_ref, recorded_at_utc
                FROM responsibility_map
                WHERE entity_name = ?
                ORDER BY id DESC
            """, (entity_name,)).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    # ── Summary ──────────────────────────────────────────────────────────────

    def entity_summary(self, entity_name: str) -> Dict[str, Any]:
        """
        Full cross-session compliance summary for an entity.
        Suitable for inclusion in RBI FREE-AI board reports.
        """
        with self._lock:
            conn = self._connect()
            row = conn.execute("""
                SELECT
                    COUNT(*)                    AS total_sessions,
                    SUM(total_decisions)        AS total_decisions,
                    SUM(human_overrides)        AS total_overrides,
                    SUM(guardrails_triggered)   AS total_guardrail_hits,
                    SUM(CASE WHEN chain_intact=0 THEN 1 ELSE 0 END) AS broken_chains,
                    MIN(recorded_at_utc)        AS first_session,
                    MAX(recorded_at_utc)        AS last_session
                FROM sessions
                WHERE entity_name = ?
            """, (entity_name,)).fetchone()
            conn.close()

        if not row or row["total_sessions"] == 0:
            return {"entity": entity_name, "total_sessions": 0}

        total_decisions = row["total_decisions"] or 0
        total_overrides = row["total_overrides"] or 0
        override_rate = round(total_overrides / total_decisions, 4) if total_decisions else 0.0
        rubber_stamps = self.rubber_stamp_sessions(entity_name)
        responsibility = self.get_responsibility_map(entity_name)

        return {
            "entity": entity_name,
            "total_sessions": row["total_sessions"],
            "total_decisions": total_decisions,
            "total_human_overrides": total_overrides,
            "override_rate": override_rate,
            "override_rate_pct": f"{override_rate * 100:.1f}%",
            "rubber_stamp_sessions": rubber_stamps,
            "rubber_stamp_flag": len(rubber_stamps) > 0,
            "total_guardrail_hits": row["total_guardrail_hits"] or 0,
            "broken_chain_sessions": row["broken_chains"] or 0,
            "first_session_utc": row["first_session"],
            "last_session_utc": row["last_session"],
            "responsibility_map": responsibility,
            "regulatory_refs": {
                "override_rate": "US SR 26-2 effective challenge; UK ICO accountability",
                "rubber_stamp":  "US SR 26-2 Sec 4.3 — human reviewer must genuinely engage",
                "responsibility": "UK ICO controller/processor; Singapore MGF Dimension 2",
            },
        }
