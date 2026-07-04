import sqlite3
import json
import threading
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime


class Database:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path, check_same_thread=False, timeout=30.0
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_schema(self):
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            conn = self._get_conn()
            conn.executescript(schema_path.read_text(encoding="utf-8"))
            conn.commit()

    @contextmanager
    def transaction(self):
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def insert_alert(self, event: dict) -> int:
        with self.transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO alerts
                   (type, process_name, pid, severity, summary, reasons,
                    shap_values, recommendation, raw_event)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.get("type", ""),
                    event.get("process_name"),
                    event.get("pid"),
                    event.get("severity", "SAFE"),
                    event.get("summary"),
                    json.dumps(event.get("reasons", [])),
                    json.dumps(event.get("shap_values", {})),
                    event.get("recommendation"),
                    json.dumps(event),
                ),
            )
            return cursor.lastrowid

    def get_alerts(self, limit=50, offset=0, severity=None) -> list:
        conn = self._get_conn()
        query = "SELECT * FROM alerts WHERE whitelisted = 0"
        params = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(row) for row in conn.execute(query, params).fetchall()]

    def get_alert(self, alert_id: int) -> dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return dict(row) if row else None

    def dismiss_alert(self, alert_id: int):
        with self.transaction() as conn:
            conn.execute(
                "UPDATE alerts SET dismissed = 1 WHERE id = ?", (alert_id,)
            )

    def insert_telemetry(self, pillar: str, snapshot: dict):
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO telemetry (pillar, snapshot) VALUES (?, ?)",
                (pillar, json.dumps(snapshot)),
            )

    def get_telemetry(self, pillar: str, limit: int = 200) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT snapshot FROM telemetry WHERE pillar = ? ORDER BY created_at DESC LIMIT ?",
            (pillar, limit),
        ).fetchall()
        return [json.loads(row["snapshot"]) for row in rows]

    def get_baseline(self, pillar: str) -> dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM baseline WHERE pillar = ?", (pillar,)
        ).fetchone()
        return dict(row) if row else None

    def save_baseline(self, pillar: str, model_bytes: bytes, feature_names: list, sample_count: int):
        with self.transaction() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO baseline
                   (pillar, model, feature_names, sample_count, fitted_at)
                   VALUES (?, ?, ?, ?, datetime('now'))""",
                (pillar, model_bytes, json.dumps(feature_names), sample_count),
            )

    def get_whitelist(self) -> set:
        conn = self._get_conn()
        rows = conn.execute("SELECT process_name FROM whitelist").fetchall()
        return {row["process_name"].lower() for row in rows}

    def add_to_whitelist(self, process_name: str):
        with self.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO whitelist (process_name) VALUES (?)",
                (process_name.lower(),),
            )

    def remove_from_whitelist(self, process_name: str):
        with self.transaction() as conn:
            conn.execute(
                "DELETE FROM whitelist WHERE process_name = ?",
                (process_name.lower(),),
            )

    def get_whitelist_all(self) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM whitelist ORDER BY added_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_setting(self, key: str, default=None) -> str:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        with self.transaction() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO settings (key, value, updated_at)
                   VALUES (?, ?, datetime('now'))""",
                (key, value),
            )

    def get_all_settings(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}

    def clear_old_telemetry(self, days: int = 7):
        with self.transaction() as conn:
            conn.execute(
                """DELETE FROM telemetry
                   WHERE created_at < datetime('now', ?)""",
                (f"-{days} days",),
            )

    def get_alert_stats(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT severity, COUNT(*) as count
               FROM alerts WHERE whitelisted = 0
               GROUP BY severity"""
        ).fetchall()
        stats = {row["severity"]: row["count"] for row in rows}
        total = conn.execute(
            "SELECT COUNT(*) as c FROM alerts WHERE whitelisted = 0"
        ).fetchone()["c"]
        stats["total"] = total
        return stats
