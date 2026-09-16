"""G5: expanded credentials must never land in the audit bundle or on stdout."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from urt.cli import main
from urt.orchestrator import Orchestrator
from urt.redaction import REDACTED, redact_run_spec_payload
from urt.types import RunSpec

SECRET_BEARER = "Bearer sk-live-bearer-0123456789"
SECRET_API_KEY = "sk-live-api-key-9876543210"
SECRET_TENANT = "tenant-guid-should-not-leak"
SECRET_ENV = "env-openai-key-should-not-leak"


def _spec_payload() -> dict:
    return {
        "name": "redaction-smoke",
        "run_profile": "pr_gate",
        "targets": [
            {
                "id": "http-agent",
                "type": "http",
                "endpoint": "http://localhost:9999/invoke",
                "auth": {"headers": {"Authorization": SECRET_BEARER}},
                "config": {"skip_healthcheck": True},
            },
            {
                "id": "foundry-agent",
                "type": "foundry",
                "endpoint": "https://foundry.example/api/chat",
                "auth": {"api_key": SECRET_API_KEY, "tenant_id": SECRET_TENANT},
                "config": {"skip_healthcheck": True},
            },
        ],
        "engines": [
            {
                "name": "promptfoo",
                "params": {
                    "command": "promptfoo --version",
                    "env": {"OPENAI_API_KEY": SECRET_ENV},
                },
            }
        ],
    }


def _assert_no_secrets(text: str) -> None:
    for secret in (SECRET_BEARER, SECRET_API_KEY, SECRET_TENANT, SECRET_ENV):
        assert secret not in text


def test_redact_run_spec_payload_masks_auth_leaves_and_sensitive_keys():
    payload = RunSpec.from_dict(_spec_payload()).to_dict()

    redacted = redact_run_spec_payload(payload)

    http_target, foundry_target = redacted["targets"]
    assert http_target["auth"] == {"headers": {"Authorization": REDACTED}}
    assert foundry_target["auth"] == {"api_key": REDACTED, "tenant_id": REDACTED}
    assert redacted["engines"][0]["params"]["env"]["OPENAI_API_KEY"] == REDACTED
    # Non-secret structure is preserved verbatim.
    assert http_target["endpoint"] == "http://localhost:9999/invoke"
    assert http_target["config"] == {"skip_healthcheck": True}
    assert redacted["engines"][0]["params"]["command"] == "promptfoo --version"
    # The caller's payload is not mutated.
    assert payload["targets"][0]["auth"]["headers"]["Authorization"] == SECRET_BEARER


def test_bundle_files_are_written_redacted(tmp_path: Path):
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"),
        metadata_db=str(tmp_path / "meta.sqlite3"),
    )
    result = orchestrator.execute(RunSpec.from_dict(_spec_payload()))
    assert result["status"] == "completed"
    run_dir = tmp_path / "artifacts" / result["run_id"]

    resolved_text = (run_dir / "resolved_spec.json").read_text(encoding="utf-8")
    manifest_text = (run_dir / "run_manifest.json").read_text(encoding="utf-8")
    _assert_no_secrets(resolved_text)
    _assert_no_secrets(manifest_text)

    resolved = json.loads(resolved_text)
    assert resolved["targets"][0]["auth"]["headers"]["Authorization"] == REDACTED
    assert resolved["targets"][1]["auth"]["api_key"] == REDACTED

    manifest = json.loads(manifest_text)
    assert manifest["bundle_format_version"] == "1.1"
    assert manifest["targets"][0]["auth"]["headers"]["Authorization"] == REDACTED
    assert manifest["targets"][1]["auth"]["tenant_id"] == REDACTED
    assert manifest["engines"][0]["params"]["env"]["OPENAI_API_KEY"] == REDACTED


def test_failed_run_manifest_is_written_redacted(tmp_path: Path):
    payload = _spec_payload()
    # A launcher that exists but exits non-zero; fail_open=false makes that fatal.
    payload["engines"] = [
        {
            "name": "garak",
            "fail_open": False,
            "params": {
                "command": f'{sys.executable} -c "raise SystemExit(3)"',
                "env": {"OPENAI_API_KEY": SECRET_ENV},
            },
        }
    ]
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"),
        metadata_db=str(tmp_path / "meta.sqlite3"),
    )
    result = orchestrator.execute(RunSpec.from_dict(payload))
    assert result["status"] == "failed"
    run_dir = tmp_path / "artifacts" / result["run_id"]

    _assert_no_secrets((run_dir / "resolved_spec.json").read_text(encoding="utf-8"))
    _assert_no_secrets((run_dir / "run_manifest.json").read_text(encoding="utf-8"))


def test_validate_stdout_is_redacted(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("URT_TEST_BEARER", SECRET_BEARER)
    spec_path = tmp_path / "spec.json"
    payload = _spec_payload()
    payload["targets"][0]["auth"]["headers"]["Authorization"] = "${URT_TEST_BEARER}"
    spec_path.write_text(json.dumps(payload), encoding="utf-8")

    assert main(["validate", "--spec", str(spec_path)]) == 0

    out = capsys.readouterr().out
    assert "Validation OK" in out
    _assert_no_secrets(out)
    assert REDACTED in out


def test_print_effective_gateway_config_is_redacted(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("URT_TEST_GATEWAY_KEY", SECRET_API_KEY)
    monkeypatch.setenv("URT_TEST_GATEWAY_BEARER", SECRET_BEARER)
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
        "      bearer_token: ${URT_TEST_GATEWAY_BEARER}\n",
        encoding="utf-8",
    )

    assert main(["serve-gateway", "--config", str(cfg_path), "--print-effective-config"]) == 0

    out = capsys.readouterr().out
    _assert_no_secrets(out)
    printed = json.loads(out)
    assert printed["gateway"]["api_key"] == REDACTED
    assert printed["targets"]["demo"]["auth"]["bearer_token"] == REDACTED
    assert printed["targets"]["demo"]["endpoint"] == "http://127.0.0.1:9999/v1/chat/completions"
