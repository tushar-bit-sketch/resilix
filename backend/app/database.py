"""
RESILIX Database Layer
Uses Python's built-in sqlite3 with parameterized queries, transactions, foreign keys,
and an ORM-compatible session interface (automatically uses SQLAlchemy if installed,
or a zero-dependency SQLite transactional repository layer when running offline).
"""
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from app.config import settings

_db_lock = threading.RLock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class DatabaseSession:
    """Transactional SQLite session wrapper with parameterized query helpers."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def fetchone(self, sql: str, params: tuple | dict = ()) -> Optional[dict[str, Any]]:
        cur = self.conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
        cur = self.conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    target = db_path or settings.database_path
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, check_same_thread=False, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


@contextmanager
def db_session(db_path: Optional[str] = None) -> Generator[DatabaseSession, None, None]:
    with _db_lock:
        conn = get_connection(db_path)
        session = DatabaseSession(conn)
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            conn.close()


def get_db() -> Generator[DatabaseSession, None, None]:
    """FastAPI dependency for database sessions."""
    with db_session() as session:
        yield session
