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

Shutdown is explicit rather than left to recovery: `stop()` refuses to start further
queued runs (their rows are marked `failed: interrupted` right away), asks the run in
flight to stop at its next stage boundary, kills the tool's process group so no engine
keeps attacking the target after the control plane is gone, and records the run as
interrupted if `execute` did not get to.
"""

from __future__ import annotations

import logging
import os
import queue
import socket
import threading
from typing import TYPE_CHECKING, Any

from .runtime import ACTIVE_TOOL_PROCESSES

if TYPE_CHECKING:  # pragma: no cover
    from .orchestrator import Orchestrator
    from .types import RunSpec

_log = logging.getLogger("urt.jobs")
_POLL_SECONDS = 0.2


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
        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._current_run_id: str | None = None
        self.worker_id = current_worker_id()

    @staticmethod
    def current_worker_id() -> str:
        return current_worker_id()

    def start(self) -> None:
        with self._lock:
            if self._stopping.is_set():
                return
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, name="urt-run-worker", daemon=True)
            self._thread.start()

    def submit(self, spec: "RunSpec") -> str:
        """Record the run as `queued` and hand it to the worker. Returns the run id."""
        if self._stopping.is_set():
            raise RuntimeError("the run worker is shutting down; the run was not queued")
        run_id = self._orchestrator.enqueue_run(spec, worker_id=self.worker_id)
        self._queue.put((run_id, spec))
        self.start()
        return run_id

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    @property
    def current_run_id(self) -> str | None:
        return self._current_run_id

    def stop(self, *, timeout: float | None = None) -> None:
        """Shut down: start nothing more, fail the still-queued rows, interrupt the run in
        flight (kill its tool process group), join the thread, and make sure that run is
        recorded as interrupted rather than left `running` for the next process to find."""
        from .orchestrator import STOPPED_MESSAGE

        self._stopping.set()
        with self._lock:
            thread = self._thread
        current = self._current_run_id
        if current is not None:
            self._orchestrator.interrupt_run(current)
            killed = ACTIVE_TOOL_PROCESSES.terminate_all()
            if killed:
                _log.warning("run %s: terminated tool process groups %s on shutdown", current, killed)
        if thread is not None and thread.is_alive():
            thread.join(timeout)
        while True:
            try:
                run_id, _spec = self._queue.get_nowait()
            except queue.Empty:
                break
            self._orchestrator.mark_run_failed(run_id, STOPPED_MESSAGE.format(status="queued"))
        if current is not None:
            self._orchestrator.mark_run_failed(current, STOPPED_MESSAGE.format(status="running"))

    def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                run_id, spec = self._queue.get(timeout=_POLL_SECONDS)
            except queue.Empty:
                continue
            if self._stopping.is_set():
                # Never start a run during shutdown; `stop()` fails the row explicitly.
                self._queue.put((run_id, spec))
                return
            self._current_run_id = run_id
            try:
                self._orchestrator.execute(spec, run_id=run_id, worker_id=self.worker_id)
            except Exception:  # noqa: BLE001 - execute records its own failures; this is the last resort
                _log.exception("run %s raised outside execute()", run_id)
                self._orchestrator.mark_run_failed(run_id, "worker error: see server log")
            finally:
                self._current_run_id = None
