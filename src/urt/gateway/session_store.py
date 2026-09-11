"""Gateway-level session store for stateful backend connectors."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SessionEntry:
    """Holds live state for a single named session."""

    client: Any  # McsCopilotClient instance for Copilot Studio
    thread_id: str | None  # Foundry Agent thread ID
    created_at: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)


class SessionStore:
    """Thread-safe store for live connector sessions with TTL-based eviction.

    Live SDK clients stay in-memory only. Optional `persist_path` keeps
    serializable `thread_id` values so Foundry threads survive process restart.
    """

    def __init__(self, ttl_seconds: float = 300.0, persist_path: str | Path | None = None) -> None:
        self._sessions: dict[str, SessionEntry] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        self._persisted_wall: dict[str, dict[str, Any]] = {}
        if self._persist_path:
            self._load_persisted()

    def get(self, session_id: str) -> SessionEntry | None:
        """Return the entry for *session_id* if it exists and is not expired."""
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is not None:
                if (time.monotonic() - entry.last_used) > self._ttl:
                    del self._sessions[session_id]
                    self._persisted_wall.pop(session_id, None)
                    self._flush_persisted_unlocked()
                    return None
                entry.last_used = time.monotonic()
                self._touch_persisted_unlocked(session_id, entry)
                return entry

            persisted = self._persisted_wall.get(session_id)
            if not persisted:
                return None
            last_used_wall = float(persisted.get("last_used_wall", 0.0))
            if (time.time() - last_used_wall) > self._ttl:
                self._persisted_wall.pop(session_id, None)
                self._flush_persisted_unlocked()
                return None
            restored = SessionEntry(client=None, thread_id=persisted.get("thread_id"))
            restored.last_used = time.monotonic()
            self._sessions[session_id] = restored
            self._touch_persisted_unlocked(session_id, restored)
            return restored

    def put(self, session_id: str, entry: SessionEntry) -> None:
        """Store *entry* under *session_id*, overwriting any previous entry."""
        with self._lock:
            entry.last_used = time.monotonic()
            self._sessions[session_id] = entry
            self._touch_persisted_unlocked(session_id, entry)

    def evict_expired(self) -> int:
        """Remove all expired entries.  Returns count of evicted sessions."""
        cutoff = time.monotonic() - self._ttl
        wall_cutoff = time.time() - self._ttl
        with self._lock:
            expired = [sid for sid, e in self._sessions.items() if e.last_used < cutoff]
            for sid in expired:
                del self._sessions[sid]
                self._persisted_wall.pop(sid, None)
            stale_persist = [
                sid for sid, payload in self._persisted_wall.items()
                if float(payload.get("last_used_wall", 0.0)) < wall_cutoff
            ]
            for sid in stale_persist:
                self._persisted_wall.pop(sid, None)
            if expired or stale_persist:
                self._flush_persisted_unlocked()
        return len(expired) + len(stale_persist)

    def clear(self) -> None:
        """Remove all sessions."""
        with self._lock:
            self._sessions.clear()
            self._persisted_wall.clear()
            self._flush_persisted_unlocked()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def __bool__(self) -> bool:
        """Always truthy — use `is not None` or `len()` to check emptiness."""
        return True

    def _touch_persisted_unlocked(self, session_id: str, entry: SessionEntry) -> None:
        if not self._persist_path:
            return
        if not entry.thread_id:
            return
        self._persisted_wall[session_id] = {
            "thread_id": entry.thread_id,
            "last_used_wall": time.time(),
        }
        self._flush_persisted_unlocked()

    def _load_persisted(self) -> None:
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            payload = json.loads(self._persist_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(payload, dict):
            return
        wall_cutoff = time.time() - self._ttl
        restored: dict[str, dict[str, Any]] = {}
        for session_id, item in payload.items():
            if not isinstance(item, dict):
                continue
            last_used_wall = float(item.get("last_used_wall", 0.0))
            thread_id = item.get("thread_id")
            if not thread_id or last_used_wall < wall_cutoff:
                continue
            restored[str(session_id)] = {
                "thread_id": str(thread_id),
                "last_used_wall": last_used_wall,
            }
        self._persisted_wall = restored

    def _flush_persisted_unlocked(self) -> None:
        if not self._persist_path:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        self._persist_path.write_text(
            json.dumps(self._persisted_wall, indent=2),
            encoding="utf-8",
        )
