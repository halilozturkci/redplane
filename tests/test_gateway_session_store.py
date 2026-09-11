"""Unit tests for urt.gateway.session_store."""

from __future__ import annotations

import time

from urt.gateway.session_store import SessionEntry, SessionStore


# ---------------------------------------------------------------------------
# SessionEntry
# ---------------------------------------------------------------------------


def test_session_entry_defaults():
    entry = SessionEntry(client=None, thread_id=None)
    assert entry.client is None
    assert entry.thread_id is None
    assert entry.created_at <= time.monotonic()
    assert entry.last_used <= time.monotonic()


def test_session_entry_stores_client():
    fake_client = object()
    entry = SessionEntry(client=fake_client, thread_id="t-1")
    assert entry.client is fake_client
    assert entry.thread_id == "t-1"


# ---------------------------------------------------------------------------
# SessionStore.put / get
# ---------------------------------------------------------------------------


def test_put_and_get_returns_entry():
    store = SessionStore(ttl_seconds=60.0)
    entry = SessionEntry(client="fake", thread_id="t-1")
    store.put("session-1", entry)
    result = store.get("session-1")
    assert result is entry


def test_get_missing_session_returns_none():
    store = SessionStore(ttl_seconds=60.0)
    assert store.get("nonexistent") is None


def test_put_overwrites_existing_session():
    store = SessionStore(ttl_seconds=60.0)
    e1 = SessionEntry(client="old", thread_id="t-1")
    e2 = SessionEntry(client="new", thread_id="t-2")
    store.put("session-1", e1)
    store.put("session-1", e2)
    result = store.get("session-1")
    assert result is e2


def test_get_updates_last_used():
    store = SessionStore(ttl_seconds=60.0)
    entry = SessionEntry(client="fake", thread_id=None)
    original_last_used = entry.last_used
    store.put("s1", entry)
    time.sleep(0.01)
    result = store.get("s1")
    assert result is not None
    assert result.last_used >= original_last_used


# ---------------------------------------------------------------------------
# TTL / expiry
# ---------------------------------------------------------------------------


def test_expired_entry_returns_none():
    store = SessionStore(ttl_seconds=0.01)
    entry = SessionEntry(client="fake", thread_id=None)
    store.put("s1", entry)
    time.sleep(0.05)
    assert store.get("s1") is None


def test_expired_entry_is_removed_from_store():
    store = SessionStore(ttl_seconds=0.01)
    entry = SessionEntry(client="fake", thread_id=None)
    store.put("s1", entry)
    time.sleep(0.05)
    store.get("s1")  # triggers removal
    assert len(store) == 0


def test_non_expired_entry_survives_get():
    store = SessionStore(ttl_seconds=60.0)
    entry = SessionEntry(client="ok", thread_id=None)
    store.put("s1", entry)
    assert store.get("s1") is not None


# ---------------------------------------------------------------------------
# evict_expired
# ---------------------------------------------------------------------------


def test_evict_expired_removes_stale_entries():
    store = SessionStore(ttl_seconds=0.01)
    store.put("s1", SessionEntry(client="a", thread_id=None))
    store.put("s2", SessionEntry(client="b", thread_id=None))
    time.sleep(0.05)
    count = store.evict_expired()
    assert count == 2
    assert len(store) == 0


def test_evict_expired_leaves_fresh_entries():
    store = SessionStore(ttl_seconds=60.0)
    store.put("s1", SessionEntry(client="a", thread_id=None))
    count = store.evict_expired()
    assert count == 0
    assert len(store) == 1


def test_evict_expired_mixed():
    store = SessionStore(ttl_seconds=0.05)
    store.put("stale", SessionEntry(client="a", thread_id=None))
    time.sleep(0.1)
    store.put("fresh", SessionEntry(client="b", thread_id=None))
    count = store.evict_expired()
    assert count == 1
    assert store.get("fresh") is not None
    assert store.get("stale") is None


# ---------------------------------------------------------------------------
# clear
# ---------------------------------------------------------------------------


def test_clear_removes_all_entries():
    store = SessionStore(ttl_seconds=60.0)
    store.put("s1", SessionEntry(client="a", thread_id=None))
    store.put("s2", SessionEntry(client="b", thread_id=None))
    store.clear()
    assert len(store) == 0


# ---------------------------------------------------------------------------
# Thread safety (basic smoke test)
# ---------------------------------------------------------------------------


def test_concurrent_puts_are_safe():
    import threading

    store = SessionStore(ttl_seconds=60.0)
    errors: list[Exception] = []

    def worker(n: int) -> None:
        try:
            for i in range(20):
                store.put(f"session-{n}-{i}", SessionEntry(client=n, thread_id=str(i)))
                store.get(f"session-{n}-{i}")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
