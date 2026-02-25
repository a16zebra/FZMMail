"""
database.py — SQLite persistence layer for FozamiMail.

Schema
------
emails    — raw email metadata + body (one row per unique Message-ID)
analyses  — LLM analysis results (one row per email, FK → emails)

Both tables use the email's Message-ID header as the stable identifier,
which prevents duplicate processing across restarts.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator

import config

# ── DDL ────────────────────────────────────────────────────────────────────

_CREATE_EMAILS = """
CREATE TABLE IF NOT EXISTS emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  TEXT    UNIQUE NOT NULL,
    subject     TEXT,
    sender      TEXT,
    received_at TEXT,
    body        TEXT,
    stored_at   TEXT    NOT NULL
)
"""

_CREATE_ANALYSES = """
CREATE TABLE IF NOT EXISTS analyses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id       TEXT    UNIQUE NOT NULL,
    category         TEXT,
    urgency          TEXT,
    summary          TEXT,
    requires_action  INTEGER NOT NULL DEFAULT 0,
    importance_score REAL    NOT NULL DEFAULT 0.0,
    raw_response     TEXT,
    created_at       TEXT    NOT NULL,
    FOREIGN KEY (message_id) REFERENCES emails (message_id)
)
"""

_CREATE_IDX_ANALYSES_CREATED = """
CREATE INDEX IF NOT EXISTS idx_analyses_created_at
    ON analyses (created_at DESC)
"""


# ── Connection helper ──────────────────────────────────────────────────────

@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    """Yield an auto-committing (or rolling-back) SQLite connection."""
    connection = sqlite3.connect(config.DB_PATH)
    connection.row_factory = sqlite3.Row
    # Enable WAL mode for better concurrent read performance.
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


# ── Public API ─────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables and indexes if they don't exist yet."""
    with _conn() as c:
        c.execute(_CREATE_EMAILS)
        c.execute(_CREATE_ANALYSES)
        c.execute(_CREATE_IDX_ANALYSES_CREATED)


def is_processed(message_id: str) -> bool:
    """Return True if this Message-ID has already been stored."""
    with _conn() as c:
        row = c.execute(
            "SELECT 1 FROM emails WHERE message_id = ?", (message_id,)
        ).fetchone()
        return row is not None


def save_email(
    message_id: str,
    subject: str,
    sender: str,
    received_at: str,
    body: str,
) -> None:
    """Persist raw email data.  Silently ignores duplicates (IGNORE)."""
    now = _utcnow()
    with _conn() as c:
        c.execute(
            """
            INSERT OR IGNORE INTO emails
                (message_id, subject, sender, received_at, body, stored_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (message_id, subject, sender, received_at, body, now),
        )


def save_analysis(
    message_id: str,
    category: str,
    urgency: str,
    summary: str,
    requires_action: bool,
    importance_score: float,
    raw_response: str,
) -> None:
    """Persist LLM analysis.  Replaces any previous analysis for the same email."""
    now = _utcnow()
    with _conn() as c:
        c.execute(
            """
            INSERT OR REPLACE INTO analyses
                (message_id, category, urgency, summary,
                 requires_action, importance_score, raw_response, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_id,
                category,
                urgency,
                summary,
                int(requires_action),
                importance_score,
                raw_response,
                now,
            ),
        )


def get_recent_analyses(limit: int = 10) -> list[dict]:
    """Return the most recently analysed emails as plain dicts."""
    with _conn() as c:
        rows = c.execute(
            """
            SELECT
                e.message_id,
                e.subject,
                e.sender,
                e.received_at,
                a.category,
                a.urgency,
                a.summary,
                a.requires_action,
                a.importance_score,
                a.created_at
            FROM emails    e
            JOIN analyses  a ON e.message_id = a.message_id
            ORDER BY a.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


# ── Helpers ────────────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
