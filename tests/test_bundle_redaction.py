"""G5: expanded credentials must never land in the audit bundle, SQLite or stdout.

The sweep is deliberately broad: every file the run writes, every SQLite row and
every CLI/API payload, with a launcher that actually executes and echoes the
secrets it received (argv, env) back through stdout/stderr.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

from urt.cli import main
from urt.config import expand_env_vars, load_run_spec
from urt.orchestrator import Orchestrator
from urt.redaction import (
    REDACTED,
    Scrubber,
    collect_secret_values,
    redact_run_spec_payload,
)
from urt.types import RunSpec, UnifiedFinding

PYTHON = sys.executable

SECRET_BEARER = "Bearer sk-live-bearer-0123456789"
SECRET_API_KEY = "sk-live-api-key-9876543210"
SECRET_TENANT = "tenant-guid-should-not-leak"
SECRET_ENDPOINT_KEY = "endpoint-query-key-abcdef123456"
SECRET_ARGV = "argv-secret-passed-on-command-line-777"
SECRET_ENGINE_ENV = "engine-env-openai-key-should-not-leak"
SECRET_EVAL_ENV = "evaluator-env-token-should-not-leak"
# An env name no key heuristic matches; the value is still a params.env value.
SECRET_PLAIN_ENV = "plain-named-env-value-should-not-leak"
ALL_SECRETS = (
    SECRET_BEARER,
    SECRET_API_KEY,
    SECRET_TENANT,
    SECRET_ENDPOINT_KEY,
    SECRET_ARGV,
    SECRET_ENGINE_ENV,
    SECRET_EVAL_ENV,
    SECRET_PLAIN_ENV,
)

# Echoes argv and the env it received to stdout/stderr, like a chatty real tool.
ECHO_LAUNCHER = (
    f"{PYTHON} -c \"import os,sys;print(sys.argv);"
    "print(os.environ.get('OPENAI_API_KEY'), os.environ.get('ECHO'));"
    "print(os.environ.get('EVAL_TOKEN'), file=sys.stderr)\""
)

ENV = {
    "URT_T_BEARER": SECRET_BEARER,
    "URT_T_API_KEY": SECRET_API_KEY,
    "URT_T_TENANT": SECRET_TENANT,
    "URT_T_ENDPOINT_KEY": SECRET_ENDPOINT_KEY,
    "URT_T_ARGV": SECRET_ARGV,
    "URT_T_ENGINE_ENV": SECRET_ENGINE_ENV,
    "URT_T_EVAL_ENV": SECRET_EVAL_ENV,
    "URT_T_PLAIN_ENV": SECRET_PLAIN_ENV,
}


def _spec_payload(*, expanded: bool) -> dict:
    """Spec with `${VAR}` placeholders (expanded=False) or literal secrets (expanded=True)."""

    def v(name: str) -> str:
        return ENV[name] if expanded else f"${{{name}}}"

    return {
        "name": "redaction-sweep",
        "run_profile": "pr_gate",
        "targets": [
            {
                "id": "http-agent",
                "type": "http",
                "endpoint": f"http://localhost:9999/invoke?api-key={v('URT_T_ENDPOINT_KEY')}",
                "auth": {"headers": {"Authorization": v("URT_T_BEARER")}},
                "config": {"skip_healthcheck": True},
            },
            {
                "id": "foundry-agent",
                "type": "foundry",
                "endpoint": "https://foundry.example/api/chat",
                "auth": {"api_key": v("URT_T_API_KEY"), "tenant_id": v("URT_T_TENANT")},
                "config": {"skip_healthcheck": True},
            },
        ],
        "engines": [
            {
                "name": "promptfoo",
                "params": {
                    "command": f"{ECHO_LAUNCHER} --api-key {v('URT_T_ARGV')}",
                    "env": {"OPENAI_API_KEY": v("URT_T_ENGINE_ENV"), "ECHO": v("URT_T_PLAIN_ENV")},
                },
            }
        ],
        "evaluators": [
            {
                "name": "custom_script",
                "params": {
                    "command": ECHO_LAUNCHER,
                    "env": {"EVAL_TOKEN": v("URT_T_EVAL_ENV")},
                },
            }
        ],
    }


def _write_spec(tmp_path: Path, payload: dict) -> Path:
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(payload), encoding="utf-8")
    return spec_path


def _set_env(monkeypatch) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)


def _assert_no_secrets(text: str, *, where: str) -> None:
    for secret in ALL_SECRETS:
        assert secret not in text, f"{secret!r} leaked into {where}"


def _sweep_run_dir(run_dir: Path) -> None:
    files = [p for p in run_dir.rglob("*") if p.is_file()]
    assert files, "run directory is empty"
    for path in files:
        _assert_no_secrets(path.read_bytes().decode("utf-8", errors="replace"), where=str(path))


def _sweep_sqlite(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        assert tables
        for table in tables:
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608 - table names come from sqlite_master
            _assert_no_secrets(repr(rows), where=f"sqlite table {table}")
    finally:
        conn.close()


# --- unit seams -----------------------------------------------------------------


def test_redact_run_spec_payload_masks_auth_leaves_and_sensitive_keys():
    payload = RunSpec.from_dict(_spec_payload(expanded=True)).to_dict()

    redacted = redact_run_spec_payload(payload)

    http_target, foundry_target = redacted["targets"]
    assert http_target["auth"] == {"headers": {"Authorization": REDACTED}}
    assert foundry_target["auth"] == {"api_key": REDACTED, "tenant_id": REDACTED}
    assert redacted["engines"][0]["params"]["env"]["OPENAI_API_KEY"] == REDACTED
    assert http_target["config"] == {"skip_healthcheck": True}
    assert payload["targets"][0]["auth"]["headers"]["Authorization"] == SECRET_BEARER


def test_collect_secret_values_takes_auth_leaves_and_sensitive_keys_and_bearer_tokens():
    values = collect_secret_values(RunSpec.from_dict(_spec_payload(expanded=True)).to_dict())

    assert {SECRET_BEARER, SECRET_API_KEY, SECRET_TENANT, SECRET_ENGINE_ENV, SECRET_EVAL_ENV} <= values
    # Every params.env value is a secret by position, whatever its name (API-literal path).
    assert SECRET_PLAIN_ENV in values
    # The bare token behind "Bearer " is a secret in its own right.
    assert SECRET_BEARER.removeprefix("Bearer ") in values
    # Values that are not credentials by key or position are not collected.
    assert "http-agent" not in values
    assert "pr_gate" not in values


def test_expand_env_vars_collects_substituted_values_of_useful_length(monkeypatch):
    monkeypatch.setenv("URT_T_LONG", "long-enough-secret-value")
    monkeypatch.setenv("URT_T_SHORT", "abc")
    collected: set[str] = set()

    expanded = expand_env_vars(
        {"command": "tool --key ${URT_T_LONG} --mode $URT_T_SHORT", "nested": ["${URT_T_LONG}"]},
        collected=collected,
    )

    assert expanded["command"] == "tool --key long-enough-secret-value --mode abc"
    assert collected == {"long-enough-secret-value"}


def test_load_run_spec_keeps_substituted_values_out_of_to_dict(tmp_path: Path, monkeypatch):
    _set_env(monkeypatch)
    spec = load_run_spec(_write_spec(tmp_path, _spec_payload(expanded=False)))

    assert SECRET_ARGV in spec.secret_values
    assert SECRET_ENDPOINT_KEY in spec.secret_values
    assert "secret_values" not in spec.to_dict()
    assert "secret_values" not in json.dumps(spec.to_dict())


def test_scrubber_replaces_values_everywhere_longest_first():
    scrubber = Scrubber(["sk-live-abcdef12", "Bearer sk-live-abcdef12", "tiny"])

    assert scrubber.scrub_text("Authorization: Bearer sk-live-abcdef12; key=sk-live-abcdef12") == (
        f"Authorization: {REDACTED}; key={REDACTED}"
    )
    assert scrubber.scrub_text("tiny stays because it is below the length floor") == (
        "tiny stays because it is below the length floor"
    )
    assert scrubber.scrub({"a": ["x sk-live-abcdef12 y", 3, None], "b": {"c": "sk-live-abcdef12"}}) == {
        "a": [f"x {REDACTED} y", 3, None],
        "b": {"c": REDACTED},
    }
    finding = UnifiedFinding(
        finding_id="f",
        run_id="r",
        target_id="t",
        engine="e",
        category="execution",
        sub_category=None,
        severity="info",
        confidence=0.5,
        attack_vector="x",
        attack_complexity="x",
        success=True,
        description="ran with sk-live-abcdef12",
        metadata={"command": ["tool", "--key", "sk-live-abcdef12"]},
    )
    scrubbed = scrubber.scrub_finding(finding)
    assert scrubbed.description == f"ran with {REDACTED}"
    assert scrubbed.metadata["command"] == ["tool", "--key", REDACTED]
    assert finding.description == "ran with sk-live-abcdef12"  # input not mutated
    assert not Scrubber([])


# --- end-to-end sweep -------------------------------------------------------------


def test_run_writes_nothing_secret_to_disk_sqlite_or_stdout(tmp_path: Path, monkeypatch, capsys):
    _set_env(monkeypatch)
    spec_path = _write_spec(tmp_path, _spec_payload(expanded=False))
    artifact_root = tmp_path / "artifacts"
    metadata_db = tmp_path / "meta.sqlite3"
    common = ["--artifact-root", str(artifact_root), "--metadata-db", str(metadata_db)]

    assert main([*common, "run", "--spec", str(spec_path)]) == 0
    run_stdout = capsys.readouterr().out
    result = json.loads(run_stdout)
    assert result["status"] == "completed"
    run_id = result["run_id"]
    run_dir = artifact_root / run_id

    # The launcher really ran and echoed its argv/env: the raw logs exist and are scrubbed.
    engine_stdout = (run_dir / "raw/promptfoo/http-agent_stdout.log").read_text(encoding="utf-8")
    assert "--api-key" in engine_stdout
    assert REDACTED in engine_stdout
    eval_stderr = (run_dir / "raw/custom_script_eval/http-agent_stderr.log").read_text(encoding="utf-8")
    assert eval_stderr.strip() == REDACTED

    _assert_no_secrets(run_stdout, where="urt run stdout")
    _sweep_run_dir(run_dir)
    _sweep_sqlite(metadata_db)

    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    engine_exec = next(f for f in findings if f["sub_category"] == "engine_runtime")
    assert "env_overrides" not in engine_exec["metadata"]
    assert engine_exec["metadata"]["env_override_keys"] == ["ECHO", "OPENAI_API_KEY"]
    assert REDACTED in engine_exec["metadata"]["command"]

    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["bundle_format_version"] == "1.1"
    assert manifest["targets"][0]["auth"]["headers"]["Authorization"] == REDACTED
    assert manifest["targets"][0]["endpoint"] == f"http://localhost:9999/invoke?api-key={REDACTED}"

    for command in (["findings", "--run-id", run_id], ["runs"], ["artifacts", "--run-id", run_id]):
        assert main([*common, *command]) == 0
        _assert_no_secrets(capsys.readouterr().out, where=f"urt {command[0]} stdout")


def test_api_submitted_spec_is_scrubbed_by_credential_values_too(tmp_path: Path):
    """No `${VAR}` knowledge here: auth values must still be scrubbed wherever they echo."""
    payload = _spec_payload(expanded=True)
    # Reuse the auth bearer token inside argv, where key heuristics cannot see it.
    payload["engines"][0]["params"]["command"] = f"{ECHO_LAUNCHER} --token {SECRET_BEARER.removeprefix('Bearer ')}"
    orchestrator = Orchestrator(artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"))

    result = orchestrator.execute(RunSpec.from_dict(payload))
    assert result["status"] == "completed"

    for secret in (SECRET_BEARER, SECRET_API_KEY, SECRET_TENANT, SECRET_ENGINE_ENV, SECRET_EVAL_ENV, SECRET_PLAIN_ENV):
        assert secret not in json.dumps(result), f"{secret!r} in execute() result"
        for path in (tmp_path / "artifacts" / result["run_id"]).rglob("*"):
            if path.is_file():
                assert secret not in path.read_bytes().decode("utf-8", errors="replace"), str(path)
    _sweep_sqlite(tmp_path / "meta.sqlite3")


def test_failed_run_writes_nothing_secret(tmp_path: Path, monkeypatch, capsys):
    _set_env(monkeypatch)
    payload = _spec_payload(expanded=False)
    # Exists, echoes the secret, exits non-zero; fail_open=false makes that fatal.
    payload["engines"] = [
        {
            "name": "garak",
            "fail_open": False,
            "params": {
                "command": f"{PYTHON} -c \"import sys;print(sys.argv);raise SystemExit(3)\" --key ${{URT_T_ARGV}}",
            },
        }
    ]
    spec_path = _write_spec(tmp_path, payload)
    artifact_root = tmp_path / "artifacts"
    metadata_db = tmp_path / "meta.sqlite3"
    common = ["--artifact-root", str(artifact_root), "--metadata-db", str(metadata_db)]

    assert main([*common, "run", "--spec", str(spec_path)]) == 1
    run_stdout = capsys.readouterr().out
    result = json.loads(run_stdout)
    assert result["status"] == "failed"

    _assert_no_secrets(run_stdout, where="urt run stdout")
    _sweep_run_dir(artifact_root / result["run_id"])
    _sweep_sqlite(metadata_db)
    manifest = json.loads((artifact_root / result["run_id"] / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["bundle_format_version"] == "1.1"
    assert manifest["engine_invocations"][0]["metrics"]["command"][-1] == REDACTED


def test_validate_stdout_is_redacted_including_argv_and_endpoint(tmp_path: Path, monkeypatch, capsys):
    _set_env(monkeypatch)
    spec_path = _write_spec(tmp_path, _spec_payload(expanded=False))

    assert main(["validate", "--spec", str(spec_path)]) == 0

    out = capsys.readouterr().out
    assert "Validation OK" in out
    _assert_no_secrets(out, where="urt validate stdout")
    assert REDACTED in out


def test_probe_stdout_is_redacted(tmp_path: Path, monkeypatch, capsys):
    _set_env(monkeypatch)
    spec_path = _write_spec(tmp_path, _spec_payload(expanded=False))

    main(["probe", "--spec", str(spec_path)])

    _assert_no_secrets(capsys.readouterr().out, where="urt probe stdout")


def test_print_effective_gateway_config_is_redacted(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("URT_TEST_GATEWAY_KEY", SECRET_API_KEY)
    monkeypatch.setenv("URT_TEST_GATEWAY_BEARER", SECRET_BEARER)
    monkeypatch.setenv("URT_TEST_GATEWAY_SUB", SECRET_TENANT)
    monkeypatch.setattr("urt.cli.serve_gateway", lambda config: None)
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        "gateway:\n"
        "  host: 127.0.0.1\n"
        "  port: 18080\n"
        "  api_key: ${URT_TEST_GATEWAY_KEY}\n"
        "routing:\n"
        "  mode: header\n"
        "  default_target: demo\n"
        "targets:\n"
        "  demo:\n"
        "    connector: openai_compatible_http\n"
        "    endpoint: http://127.0.0.1:9999/v1/chat/completions\n"
        "    auth:\n"
        "      bearer_token: ${URT_TEST_GATEWAY_BEARER}\n"
        "      headers:\n"
        "        Ocp-Apim-Subscription-Key: ${URT_TEST_GATEWAY_SUB}\n",
        encoding="utf-8",
    )

    assert main(["serve-gateway", "--config", str(cfg_path), "--print-effective-config"]) == 0

    out = capsys.readouterr().out
    _assert_no_secrets(out, where="--print-effective-config stdout")
    printed = json.loads(out)
    assert printed["gateway"]["api_key"] == REDACTED
    assert printed["targets"]["demo"]["auth"]["bearer_token"] == REDACTED
    # Every auth leaf is masked, not only key-heuristic matches.
    assert printed["targets"]["demo"]["auth"]["headers"]["Ocp-Apim-Subscription-Key"] == REDACTED
    assert printed["targets"]["demo"]["endpoint"] == "http://127.0.0.1:9999/v1/chat/completions"
