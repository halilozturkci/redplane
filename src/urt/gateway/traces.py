"""Read-only index over the gateway audit root (G10 / §4.8).

`GatewayAuditStore` writes `<artifact_root>/YYYYMMDD/trace-<UTC stamp>-<trace_id>.json`
with headers redacted and bodies truncated. This module only *reads* that tree, so the
control-plane API can browse traces while the gateway is down or on another
machine (given the same directory). Nothing here rewrites a trace.

Two joins to a run are offered, and each match says which one produced it:

- `run_id` — the gateway stores the `X-URT-Run-Id` request header (or
  `context.run_id`) on the trace. Engines get `URT_RUN_ID` in their environment
  (`runtime.build_runtime_env`) and can forward it (Promptfoo: a provider
  `headers:` entry). Exact.
- `time_window` — untagged traces whose stamp falls inside the run's
  `[started, ended]` window. Weaker; labelled as such.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DAY_RE = re.compile(r"^\d{8}$")
TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
TRACE_FILE_RE = re.compile(r"^trace-(?P<stamp>\d{8}T\d{6}\d{6}Z)-(?P<trace_id>[0-9a-f]{32})\.json$")
SUMMARY_FIELDS = ("trace_id", "timestamp_utc", "target_id", "connector", "route_source", "status_code", "latency_ms", "run_id")


class TracePathError(ValueError):
    """A client-supplied day or trace id that is not in the fixed alphabet."""


def check_day(day: str) -> str:
    if not DAY_RE.fullmatch(day or ""):
        raise TracePathError("day must be YYYYMMDD")
    return day


def check_trace_id(trace_id: str) -> str:
    if not TRACE_ID_RE.fullmatch(trace_id or ""):
        raise TracePathError("trace id must be 32 lowercase hex characters")
    return trace_id


def _stamp_to_datetime(stamp: str) -> datetime:
    return datetime.strptime(stamp, "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class TraceFile:
    day: str
    path: Path
    stamp: datetime
    trace_id: str

    @property
    def relative_path(self) -> str:
        return f"{self.day}/{self.path.name}"


class TraceIndex:
    """Browse gateway traces under `root`; tolerant of a root that does not exist yet."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # --- listing -------------------------------------------------------------------

    def _day_dirs(self) -> list[Path]:
        if not self.root.is_dir():
            return []
        return sorted(
            (p for p in self.root.iterdir() if p.is_dir() and not p.is_symlink() and DAY_RE.fullmatch(p.name)),
            key=lambda p: p.name,
            reverse=True,
        )

    def _files(self, day: str) -> list[TraceFile]:
        day_dir = self.root / check_day(day)
        if not day_dir.is_dir() or day_dir.is_symlink():
            return []
        files: list[TraceFile] = []
        for path in day_dir.iterdir():
            match = TRACE_FILE_RE.fullmatch(path.name)
            if match is None or not path.is_file() or path.is_symlink():
                continue
            files.append(TraceFile(day=day, path=path, stamp=_stamp_to_datetime(match["stamp"]), trace_id=match["trace_id"]))
        files.sort(key=lambda item: (item.stamp, item.trace_id))
        return files

    def days(self) -> list[dict[str, Any]]:
        """Newest day first, with the number of trace files in each."""
        return [{"day": day_dir.name, "count": len(self._files(day_dir.name))} for day_dir in self._day_dirs()]

    def _read(self, item: TraceFile) -> dict[str, Any] | None:
        try:
            payload = json.loads(item.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        payload.setdefault("trace_id", item.trace_id)
        payload.setdefault("timestamp_utc", item.stamp.isoformat())
        payload["day"] = item.day
        # Relative to the audit root: never an absolute server path.
        payload["audit_path"] = item.relative_path
        return payload

    @staticmethod
    def _summary(payload: dict[str, Any]) -> dict[str, Any]:
        row = {key: payload.get(key) for key in SUMMARY_FIELDS}
        row["day"] = payload.get("day")
        row["audit_path"] = payload.get("audit_path")
        row["error"] = bool(payload.get("error"))
        return row

    def list_day(
        self,
        day: str,
        *,
        target_id: str | None = None,
        status_code: int | None = None,
        run_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Summary rows for one day, oldest first, optionally filtered."""
        rows: list[dict[str, Any]] = []
        for item in self._files(day):
            payload = self._read(item)
            if payload is None:
                continue
            if target_id and str(payload.get("target_id", "")) != target_id:
                continue
            if status_code is not None and payload.get("status_code") != status_code:
                continue
            if run_id and str(payload.get("run_id") or "") != run_id:
                continue
            rows.append(self._summary(payload))
        return rows

    def get(self, trace_id: str) -> dict[str, Any] | None:
        """The trace as stored (already redacted/truncated by the gateway); None if absent."""
        check_trace_id(trace_id)
        for day_dir in self._day_dirs():
            for item in self._files(day_dir.name):
                if item.trace_id == trace_id:
                    return self._read(item)
        return None

    def get_on_day(self, day: str, trace_id: str) -> dict[str, Any] | None:
        check_trace_id(trace_id)
        for item in self._files(day):
            if item.trace_id == trace_id:
                return self._read(item)
        return None

    # --- run linking ---------------------------------------------------------------

    def traces_for_run(self, run_id: str, *, started_at: str | None, ended_at: str | None) -> dict[str, Any]:
        """Trace ids linked to `run_id`. Only the day directories the run's window touches
        are scanned. A trace **tagged** with this run id counts wherever it sits on those
        days (`by_run_id`, exact); an **untagged** trace counts only inside `[started,
        ended]` (`by_time_window`, weaker). Traces tagged for another run are skipped.
        `all_trace_ids` is the union; the manifest's top-level `trace_ids` is `by_run_id`
        only, because a window guess is not evidence that the request belonged to the run."""
        start = _parse_iso(started_at)
        end = _parse_iso(ended_at)
        by_run_id: list[str] = []
        by_window: list[str] = []
        if start is not None and end is not None and end >= start:
            for day_dir in self._day_dirs():
                day_start = datetime.strptime(day_dir.name, "%Y%m%d").replace(tzinfo=timezone.utc)
                if day_start.date() < start.date() or day_start.date() > end.date():
                    continue
                for item in self._files(day_dir.name):
                    payload = self._read(item)
                    if payload is None:
                        continue
                    tagged = payload.get("run_id")
                    if tagged == run_id:
                        by_run_id.append(item.trace_id)
                    elif not tagged and start <= item.stamp <= end:
                        by_window.append(item.trace_id)
        return {
            "window": {"from": started_at, "to": ended_at},
            "by_run_id": sorted(by_run_id),
            "by_time_window": sorted(by_window),
            "all_trace_ids": sorted(set(by_run_id) | set(by_window)),
        }

    def summaries_for(self, link: dict[str, Any]) -> list[dict[str, Any]]:
        """Summary rows for a `traces_for_run` result, each with its `link` kind."""
        rows: list[dict[str, Any]] = []
        tagged = set(link.get("by_run_id") or [])
        for trace_id in link.get("all_trace_ids") or []:
            if not TRACE_ID_RE.match(str(trace_id)):
                continue
            payload = self.get(str(trace_id))
            if payload is None:
                rows.append({"trace_id": trace_id, "missing": True, "link": "run_id" if trace_id in tagged else "time_window"})
                continue
            rows.append({**self._summary(payload), "link": "run_id" if trace_id in tagged else "time_window"})
        return rows
