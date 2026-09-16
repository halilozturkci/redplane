"""G10 / §4.8: read-only gateway trace index in the control plane, gateway `GET /v1/sessions`,
`trace_ids` in `run_manifest.json` (next-development idea 3) and run↔trace linking.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib import error, request

import pytest
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.gateway.app import UniversalGateway, create_http_server
from urt.gateway.audit import GatewayAuditStore
from urt.gateway.config import GatewayAuditConfig, GatewayConfig
from urt.gateway.session_store import SessionEntry, SessionStore
from urt.gateway.traces import TraceIndex, TracePathError
from urt.orchestrator import Orchestrator
from urt.types import RunSpec

PYTHON = sys.executable
ADVERSARIAL = "<script>alert('trace')</script>"


def write_trace(root: Path, *, trace_id: str, at: datetime, target_id: str = "mcs", status_code: int = 200, run_id: str | None = None, body: str = "hello") -> Path:
    """A trace file in the exact shape `GatewayAuditStore.write_trace` produces."""
    day_dir = root / at.strftime("%Y%m%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    path = day_dir / f"trace-{at.strftime('%Y%m%dT%H%M%S%fZ')}-{trace_id}.json"
    payload = {
        "trace_id": trace_id,
        "timestamp_utc": at.isoformat(),
        "target_id": target_id,
        "connector": "openai_compatible_http",
        "route_source": "header",
        "latency_ms": 12.5,
        "status_code": status_code,
        "run_id": run_id,
        "request": {
            "path": "/v1/chat/completions",
            "headers": {"authorization": "***REDACTED***", "x-urt-target": target_id, "user-agent": ADVERSARIAL},
            "body": json.dumps({"messages": [{"role": "user", "content": body}]}),
        },
        "response": {"body": json.dumps({"choices": [{"message": {"content": ADVERSARIAL}}]})},
        "error": None if status_code == 200 else {"error": "upstream", "message": "boom"},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


TID = [f"{i:032x}" for i in range(1, 8)]


@pytest.fixture
def trace_root(tmp_path: Path) -> Path:
    root = tmp_path / "gateway"
    day1 = datetime(2026, 9, 15, 10, 0, tzinfo=timezone.utc)
    day2 = datetime(2026, 9, 16, 9, 0, tzinfo=timezone.utc)
    write_trace(root, trace_id=TID[0], at=day1, target_id="mcs")
    write_trace(root, trace_id=TID[1], at=day1 + timedelta(minutes=1), target_id="foundry", status_code=502)
    write_trace(root, trace_id=TID[2], at=day2, target_id="mcs", run_id="run-abc")
    write_trace(root, trace_id=TID[3], at=day2 + timedelta(seconds=30), target_id="mcs")
    write_trace(root, trace_id=TID[4], at=day2 + timedelta(seconds=45), target_id="mcs", run_id="run-other")
    (root / "notes.txt").write_text("not a day dir", encoding="utf-8")
    (root / "20260916" / "stray.json").write_text("{}", encoding="utf-8")
    return root


def test_trace_index_lists_days_filters_and_reads_details_as_stored(trace_root: Path):
    index = TraceIndex(trace_root)
    assert index.days() == [{"day": "20260916", "count": 3}, {"day": "20260915", "count": 2}]

    rows = index.list_day("20260915")
    assert [row["trace_id"] for row in rows] == [TID[0], TID[1]]
    assert set(rows[0]) >= {"trace_id", "timestamp_utc", "target_id", "connector", "route_source", "status_code", "latency_ms", "run_id", "day"}
    assert "request" not in rows[0] and "response" not in rows[0]

    assert [r["trace_id"] for r in index.list_day("20260915", target_id="foundry")] == [TID[1]]
    assert [r["trace_id"] for r in index.list_day("20260915", status_code=502)] == [TID[1]]
    assert [r["trace_id"] for r in index.list_day("20260916", run_id="run-abc")] == [TID[2]]
    assert index.list_day("20260101") == []

    detail = index.get(TID[1])
    assert detail is not None
    assert detail["status_code"] == 502
    assert detail["request"]["headers"]["authorization"] == "***REDACTED***"
    assert detail["error"]["message"] == "boom"
    assert detail["day"] == "20260915"
    assert detail["audit_path"] == f"20260915/trace-20260915T100100000000Z-{TID[1]}.json"
    assert not Path(detail["audit_path"]).is_absolute()
    assert index.get("0" * 32) is None


@pytest.mark.parametrize("day", ["../20260916", "2026091", "20260916x", "..", "", "2026/0916"])
def test_trace_index_rejects_malformed_day_segments(trace_root: Path, day: str):
    with pytest.raises(TracePathError):
        TraceIndex(trace_root).list_day(day)


@pytest.mark.parametrize("trace_id", ["../x", "abc", "X" * 32, "0" * 31, "../../etc/passwd"])
def test_trace_index_rejects_malformed_trace_ids(trace_root: Path, trace_id: str):
    with pytest.raises(TracePathError):
        TraceIndex(trace_root).get(trace_id)


def test_trace_index_tolerates_a_missing_root(tmp_path: Path):
    index = TraceIndex(tmp_path / "nope")
    assert index.days() == []
    assert index.list_day("20260916") == []
    assert index.get(TID[0]) is None


def test_traces_for_run_matches_by_run_id_tag_and_by_time_window(trace_root: Path):
    index = TraceIndex(trace_root)
    window_start = datetime(2026, 9, 16, 8, 59, tzinfo=timezone.utc)
    window_end = datetime(2026, 9, 16, 9, 1, tzinfo=timezone.utc)
    link = index.traces_for_run("run-abc", started_at=window_start.isoformat(), ended_at=window_end.isoformat())
    assert link["by_run_id"] == [TID[2]]
    # Untagged traces inside the window are offered as a weaker, time-based join; a
    # trace tagged with another run is not.
    assert link["by_time_window"] == [TID[3]]
    assert link["trace_ids"] == sorted([TID[2], TID[3]])
    assert link["window"] == {"from": window_start.isoformat(), "to": window_end.isoformat()}


def test_gateway_audit_store_records_run_id_and_relative_audit_path(tmp_path: Path):
    store = GatewayAuditStore(GatewayAuditConfig(artifact_root=str(tmp_path / "gw")))
    relative = store.write_trace("f" * 32, {"trace_id": "f" * 32, "request": {"headers": {}, "body": {}}, "response": {"body": {}}})
    assert not Path(relative).is_absolute()
    assert relative.endswith(f"-{'f' * 32}.json")
    assert (tmp_path / "gw" / relative).is_file()


def _gateway(tmp_path: Path, backend_base: str, *, api_key: str | None = None, persist: bool = False) -> GatewayConfig:
    gateway = {"host": "127.0.0.1", "port": 0}
    if api_key:
        gateway["api_key"] = api_key
    if persist:
        gateway["session_persist_path"] = str(tmp_path / "sessions.json")
    return GatewayConfig.from_dict(
        {
            "gateway": gateway,
            "routing": {"mode": "header", "header_name": "X-URT-Target", "default_target": "mock-openai"},
            "audit": {"artifact_root": str(tmp_path / "gateway_audit")},
            "targets": {"mock-openai": {"connector": "openai_compatible_http", "endpoint": f"{backend_base}/openai/chat/completions"}},
        }
    )


def test_gateway_tags_traces_with_run_id_and_returns_a_relative_audit_path(tmp_path: Path):
    from test_gateway_connectors_and_app import _start_mock_backend

    backend_server, backend_thread, _ = _start_mock_backend()
    backend_base = f"http://127.0.0.1:{backend_server.server_address[1]}"
    gateway = UniversalGateway(_gateway(tmp_path, backend_base))
    server = create_http_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        req = request.Request(
            url=f"http://127.0.0.1:{port}/v1/chat/completions",
            method="POST",
            data=json.dumps({"model": "m", "messages": [{"role": "user", "content": "ping"}]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-URT-Target": "mock-openai", "X-URT-Run-Id": "run-from-engine"},
        )
        with request.urlopen(req, timeout=5) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
        audit_path = payload["metadata"]["audit_path"]
        assert not Path(audit_path).is_absolute()
        assert str(tmp_path) not in audit_path
        trace = json.loads((tmp_path / "gateway_audit" / audit_path).read_text(encoding="utf-8"))
        assert trace["run_id"] == "run-from-engine"
        assert trace["trace_id"] == payload["metadata"]["trace_id"]

        index = TraceIndex(tmp_path / "gateway_audit")
        [row] = index.list_day(trace["timestamp_utc"][:10].replace("-", ""), run_id="run-from-engine")
        assert row["trace_id"] == trace["trace_id"]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        backend_server.shutdown()
        backend_thread.join(timeout=5)


def test_session_store_describe_exposes_identifiers_and_presence_only(tmp_path: Path):
    store = SessionStore(ttl_seconds=60.0, persist_path=tmp_path / "sessions.json")
    store.put("copilot-1", SessionEntry(client=object(), thread_id=None))
    store.put("foundry-1", SessionEntry(client=None, thread_id="thread_secret_content"))
    rows = store.describe()
    by_id = {row["session_id"]: row for row in rows}
    assert set(by_id) == {"copilot-1", "foundry-1"}
    assert by_id["copilot-1"]["live_client_present"] is True and by_id["copilot-1"]["thread_id_present"] is False
    assert by_id["foundry-1"]["live_client_present"] is False and by_id["foundry-1"]["thread_id_present"] is True
    assert "thread_secret_content" not in json.dumps(rows)
    assert "client" not in by_id["copilot-1"] and "thread_id" not in by_id["foundry-1"]
    assert by_id["foundry-1"]["last_used_utc"].endswith("+00:00")
    assert by_id["foundry-1"]["idle_seconds"] >= 0

    # A persisted-only Foundry thread (another process wrote it) is listed as such.
    restored = SessionStore(ttl_seconds=60.0, persist_path=tmp_path / "sessions.json")
    [row] = restored.describe()
    assert row["session_id"] == "foundry-1" and row["source"] == "persisted" and row["thread_id_present"] is True


def test_gateway_sessions_endpoint_lists_sessions_without_content_and_honours_the_api_key(tmp_path: Path):
    from test_gateway_connectors_and_app import _start_mock_backend

    backend_server, backend_thread, _ = _start_mock_backend()
    backend_base = f"http://127.0.0.1:{backend_server.server_address[1]}"
    gateway = UniversalGateway(_gateway(tmp_path, backend_base, api_key="gw-secret-key-0123456789"))
    gateway.session_store.put("s-1", SessionEntry(client=None, thread_id="thread-xyz"))
    server = create_http_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/v1/sessions"
        with pytest.raises(error.HTTPError) as denied:
            request.urlopen(request.Request(url, method="GET"), timeout=5)  # noqa: S310
        assert denied.value.code == 401
        with request.urlopen(request.Request(url, headers={"Authorization": "Bearer gw-secret-key-0123456789"}), timeout=5) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["count"] == 1
        assert payload["ttl_seconds"] == 300.0
        [row] = payload["sessions"]
        assert row["session_id"] == "s-1" and row["thread_id_present"] is True and row["live_client_present"] is False
        assert "thread-xyz" not in json.dumps(payload)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        backend_server.shutdown()
        backend_thread.join(timeout=5)


def _run_spec(name: str = "linked") -> dict:
    return {
        "name": name,
        "run_profile": "pr_gate",
        "targets": [{"id": "mcs", "type": "http", "endpoint": "http://localhost:9999/invoke", "config": {"skip_healthcheck": True}}],
        "engines": [{"name": "garak", "params": {"command": f"{PYTHON} -c \"print('garak-ok')\""}}],
    }


TRACE_WRITER = """
import json, os, sys
from datetime import datetime, timezone
sys.path.insert(0, sys.argv[2])
from test_gateway_traces import write_trace, TID
from pathlib import Path
root = Path(sys.argv[1])
now = datetime.now(timezone.utc)
# What an attack tool that forwarded URT_RUN_ID as X-URT-Run-Id would leave behind,
# next to an untagged request and one belonging to another run.
write_trace(root, trace_id=TID[1], at=now, target_id="mcs", run_id=os.environ["URT_RUN_ID"])
write_trace(root, trace_id=TID[2], at=now, target_id="mcs")
write_trace(root, trace_id=TID[3], at=now, target_id="mcs", run_id="run-someone-else")
print("garak-ok")
"""


def test_run_manifest_records_gateway_trace_ids_and_runtime_env_carries_the_run_id(tmp_path: Path, monkeypatch):
    from urt.adapters.engine_base import EngineContext
    from urt.runtime import build_runtime_env

    root = tmp_path / "gateway"
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"), gateway_trace_root=str(root)
    )
    writer = tmp_path / "trace_writer.py"
    writer.write_text(TRACE_WRITER, encoding="utf-8")
    payload = _run_spec()
    payload["engines"][0]["params"]["command"] = f"{PYTHON} {writer} {root} {Path(__file__).parent}"
    spec = RunSpec.from_dict(payload)
    run_id = orchestrator.enqueue_run(spec, worker_id="h:1")
    write_trace(root, trace_id=TID[0], at=datetime.now(timezone.utc) - timedelta(hours=2), target_id="mcs")
    result = orchestrator.execute(spec, run_id=run_id)
    assert result["status"] == "completed"

    manifest = json.loads((tmp_path / "artifacts" / run_id / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["trace_ids"] == sorted([TID[1], TID[2]])
    assert manifest["gateway_traces"]["by_run_id"] == [TID[1]]
    assert manifest["gateway_traces"]["by_time_window"] == [TID[2]]
    assert manifest["gateway_traces"]["trace_root"] == str(root)
    assert str(tmp_path) not in json.dumps(manifest["gateway_traces"]["by_run_id"])

    linked = orchestrator.run_traces(run_id)
    assert linked["trace_ids"] == manifest["trace_ids"]
    assert [row["trace_id"] for row in linked["traces"]] == manifest["trace_ids"]
    assert linked["traces"][0]["link"] in {"run_id", "time_window"}

    context = EngineContext(
        run_id=run_id,
        run_name="linked",
        run_profile="pr_gate",
        target=spec.targets[0],
        artifact_store=orchestrator.artifact_store,
        timeout_seconds=10,
        seed=None,
    )
    assert build_runtime_env(context)["URT_RUN_ID"] == run_id


def test_failed_run_manifest_also_records_trace_ids(tmp_path: Path):
    root = tmp_path / "gateway"
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"), gateway_trace_root=str(root)
    )
    spec = _run_spec("broken")
    writer = tmp_path / "trace_writer.py"
    writer.write_text(TRACE_WRITER.replace('TID[1], at=now, target_id="mcs", run_id=os.environ["URT_RUN_ID"]', 'TID[5], at=now, target_id="mcs"').replace('print("garak-ok")', "raise SystemExit(3)"), encoding="utf-8")
    spec["engines"] = [{"name": "garak", "fail_open": False, "params": {"command": f"{PYTHON} {writer} {root} {Path(__file__).parent}"}}]
    result = orchestrator.execute(RunSpec.from_dict(spec))
    assert result["status"] == "failed"
    manifest = json.loads((tmp_path / "artifacts" / result["run_id"] / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["trace_ids"] == sorted([TID[2], TID[5]])
    assert manifest["gateway_traces"]["by_run_id"] == []


# --- control-plane API and /ui pages -------------------------------------------------------


@pytest.fixture
def api(trace_root: Path, tmp_path: Path, monkeypatch) -> tuple[TestClient, Orchestrator]:
    monkeypatch.delenv("URT_GATEWAY_URL", raising=False)
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"), gateway_trace_root=str(trace_root)
    )
    return TestClient(create_app(orchestrator)), orchestrator


def test_trace_api_is_read_only_and_works_without_a_gateway(api):
    client, _ = api
    days = client.get("/v1/traces")
    assert days.status_code == 200
    assert days.json()["days"] == [{"day": "20260916", "count": 3}, {"day": "20260915", "count": 2}]
    assert "trace_root" in days.json()

    listing = client.get("/v1/traces/20260915")
    assert listing.status_code == 200
    assert [row["trace_id"] for row in listing.json()] == [TID[0], TID[1]]
    assert [row["trace_id"] for row in client.get("/v1/traces/20260915", params={"status_code": 502}).json()] == [TID[1]]
    assert [row["trace_id"] for row in client.get("/v1/traces/20260915", params={"target_id": "mcs"}).json()] == [TID[0]]
    assert client.get("/v1/traces/20260915", params={"status_code": "x"}).status_code == 422  # FastAPI typed query

    detail = client.get(f"/v1/traces/20260915/{TID[1]}")
    assert detail.status_code == 200
    assert detail.json()["request"]["headers"]["authorization"] == "***REDACTED***"
    assert detail.json()["audit_path"].startswith("20260915/")
    assert client.get(f"/v1/traces/20260916/{TID[1]}").status_code == 404  # wrong day
    assert client.get("/v1/traces/20260915/nope").status_code == 400
    assert client.get("/v1/traces/..%2F20260915").status_code in {400, 404}
    assert client.post("/v1/traces/20260915", json={}).status_code == 405


def test_sessions_proxy_reports_when_no_gateway_is_configured(api):
    client, _ = api
    response = client.get("/v1/gateway/sessions")
    assert response.status_code == 503
    assert "URT_GATEWAY_URL" in response.json()["detail"]


def test_sessions_proxy_reads_the_gateway_when_configured(tmp_path: Path, monkeypatch, trace_root: Path):
    from test_gateway_connectors_and_app import _start_mock_backend

    backend_server, backend_thread, _ = _start_mock_backend()
    backend_base = f"http://127.0.0.1:{backend_server.server_address[1]}"
    gateway = UniversalGateway(_gateway(tmp_path, backend_base, api_key="gw-secret-key-0123456789"))
    gateway.session_store.put("s-1", SessionEntry(client=object(), thread_id=None))
    server = create_http_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("URT_GATEWAY_URL", f"http://127.0.0.1:{server.server_address[1]}")
        monkeypatch.setenv("URT_GATEWAY_API_KEY", "gw-secret-key-0123456789")
        orchestrator = Orchestrator(
            artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"), gateway_trace_root=str(trace_root)
        )
        client = TestClient(create_app(orchestrator))
        payload = client.get("/v1/gateway/sessions").json()
        assert payload["count"] == 1
        assert payload["sessions"][0]["live_client_present"] is True

        page = client.get("/ui/traces")
        assert page.status_code == 200
        assert "s-1" in page.text and "live client" in page.text
    finally:
        server.shutdown()
        thread.join(timeout=5)
        backend_server.shutdown()
        backend_thread.join(timeout=5)


def test_ui_trace_pages_render_escaped_and_link_runs_to_their_traces(api, tmp_path: Path):
    client, orchestrator = api
    days = client.get("/ui/traces")
    assert days.status_code == 200
    assert 'href="/ui/traces/20260916"' in days.text
    assert "Gateway sessions" in days.text and "URT_GATEWAY_URL" in days.text

    listing = client.get("/ui/traces/20260915")
    assert listing.status_code == 200
    assert f'href="/ui/traces/20260915/{TID[1]}"' in listing.text
    assert "502" in listing.text and "foundry" in listing.text
    filtered = client.get("/ui/traces/20260915", params={"target_id": "foundry"})
    assert TID[0] not in filtered.text and TID[1] in filtered.text

    detail = client.get(f"/ui/traces/20260915/{TID[1]}")
    assert detail.status_code == 200
    assert "&lt;script&gt;alert(&#39;trace&#39;)&lt;/script&gt;" in detail.text
    assert ADVERSARIAL not in detail.text
    assert "***REDACTED***" in detail.text
    assert "as stored" in detail.text
    assert str(tmp_path) not in detail.text
    assert client.get("/ui/traces/20260915/" + "0" * 32).status_code == 404
    assert client.get("/ui/traces/2026").status_code == 400

    # Run ↔ trace linking on the run page and the traces page.
    spec = RunSpec.from_dict(_run_spec())
    run_id = orchestrator.enqueue_run(spec, worker_id="h:1")
    write_trace(orchestrator.gateway_traces.root, trace_id=TID[6], at=datetime.now(timezone.utc), target_id="mcs", run_id=run_id)
    assert orchestrator.execute(spec, run_id=run_id)["status"] == "completed"
    run_page = client.get(f"/ui/runs/{run_id}")
    assert f'href="/ui/traces?run_id={run_id}"' in run_page.text
    assert "Gateway traces (1)" in run_page.text
    linked = client.get("/ui/traces", params={"run_id": run_id})
    assert linked.status_code == 200
    assert TID[6] in linked.text and "run_id" in linked.text
    api_linked = client.get(f"/v1/runs/{run_id}/traces").json()
    assert api_linked["trace_ids"] == [TID[6]]
    assert api_linked["traces"][0]["link"] == "run_id"
