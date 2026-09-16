"""Background execution for `POST /v1/runs` (G7 / #18).

One worker thread per control-plane process drains an in-memory FIFO and calls the
same `Orchestrator.execute` that `urt run` uses — there is no second execution
path. SQLite (`runs.status`) is the only shared state: `queued` on submit,
`running` when the worker picks the run up, `completed` / `failed` when
`execute` returns. No Redis, no separate process: local-first, one operator.

The queue holds the expanded `RunSpec` (it carries credentials) **in memory only**;
nothing about a queued run is persisted besides its SQLite row. A process that dies
with runs still `queued` or `running` therefore cannot resume them; the next
process marks them `failed` with an explicit "interrupted" message
(`Orchestrator.recover_interrupted_runs`) instead of re-executing them (duplicate
bundles) or leaving them `running` forever. Rows record `worker_id`
(`<hostname>:<pid>`) so that recovery only touches runs whose process is gone and
never a run that `urt run` is executing right now in another process.
"""

from __future__ import annotations

import logging
import os
import queue
import socket
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .orchestrator import Orchestrator
    from .types import RunSpec

_log = logging.getLogger("urt.jobs")
_STOP = object()


def current_worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def worker_is_alive(worker_id: str | None) -> bool | None:
    """True/False when the worker ran on this host and its pid can be checked; None when
    the id is missing/malformed or names another host (unknowable from here)."""
    if not worker_id or ":" not in worker_id:
        return None
    host, _, pid_text = worker_id.rpartition(":")
    if not pid_text.isdigit():
        return None
    if host != socket.gethostname():
        return None
    return _pid_alive(int(pid_text))


class RunWorker:
    """Single background thread that executes queued runs in submission order."""

    def __init__(self, orchestrator: "Orchestrator") -> None:
        self._orchestrator = orchestrator
        self._queue: queue.Queue[Any] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.worker_id = current_worker_id()

    @staticmethod
    def current_worker_id() -> str:
        return current_worker_id()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, name="urt-run-worker", daemon=True)
            self._thread.start()

    def stop(self, *, timeout: float | None = None) -> None:
        """Ask the thread to exit after the run it is executing (if any) and join it."""
        with self._lock:
            thread = self._thread
        if thread is None or not thread.is_alive():
            return
        self._queue.put(_STOP)
        thread.join(timeout)

    def submit(self, spec: "RunSpec") -> str:
        """Record the run as `queued` and hand it to the worker. Returns the run id."""
        run_id = self._orchestrator.enqueue_run(spec, worker_id=self.worker_id)
        self._queue.put((run_id, spec))
        self.start()
        return run_id

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            run_id, spec = item
            try:
                self._orchestrator.execute(spec, run_id=run_id, worker_id=self.worker_id)
            except Exception:  # noqa: BLE001 - execute records its own failures; this is the last resort
                _log.exception("run %s raised outside execute()", run_id)
                self._orchestrator.mark_run_failed(run_id, "worker error: see server log")
