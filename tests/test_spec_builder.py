"""v1 §4.7 / G4: spec builder — capabilities, templates, validate-only, probe, `/ui/specs`.

Hard rule under test: the browser never sees an expanded secret. Auth fields accept
`${VAR}` references only; the validate response says whether a variable is set
(boolean), never its value; the resolved spec is redacted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import Bundle
from fastapi.testclient import TestClient

from urt import constants
from urt.api import create_app
from urt.specs import capabilities, form_to_payload, payload_to_form, validate_spec_payload

SECRET = "sk-live-0123456789abcdef"


@pytest.fixture
def client(orchestrator, monkeypatch, tmp_path: Path) -> TestClient:
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "run_spec.smoke.yaml").write_text(
        "name: smoke\nrun_profile: nightly\nmetadata:\n  spec_kind: smoke\n  description: launcher presence only\n"
        "targets:\n  - id: t\n    type: http\n    endpoint: http://localhost:1/x\n    config: {skip_healthcheck: true}\n"
        "engines:\n  - name: garak\n    params: {command: garak --version}\n",
        encoding="utf-8",
    )
    (templates / "run_spec.mcs_real.sample.yaml").write_text(
        "name: mcs-real\nrun_profile: nightly\ntargets:\n  - id: mcs\n    type: copilot\n    config: {mode: sdk, skip_healthcheck: true}\n"
        "engines:\n  - name: pyrit\n    params: {script_path: x.py}\n",
        encoding="utf-8",
    )
    (templates / "gateway_config.sample.yaml").write_text("gateway: {}\n", encoding="utf-8")
    (templates / "notes.txt").write_text("not a spec", encoding="utf-8")
    monkeypatch.setenv("URT_TEMPLATES_DIR", str(templates))
    monkeypatch.setenv("REDPLANE_TEST_TOKEN", SECRET)
    monkeypatch.delenv("REDPLANE_UNSET_TOKEN", raising=False)
    return TestClient(create_app(orchestrator))


def _spec(auth: dict | None = None, **overrides) -> dict:
    payload = {
        "name": "builder-spec",
        "run_profile": "pr_gate",
        "targets": [
            {
                "id": "agent",
                "type": "http",
                "endpoint": "http://localhost:9999/invoke",
                "auth": auth if auth is not None else {"headers": {"Authorization": "Bearer ${REDPLANE_TEST_TOKEN}"}},
                "config": {"skip_healthcheck": True},
            }
        ],
        "engines": [{"name": "garak", "params": {"command": "garak --version"}}],
    }
    payload.update(overrides)
    return payload


def test_capabilities_come_from_constants(client: TestClient):
    response = client.get("/v1/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert set(body["targets"]) == constants.SUPPORTED_TARGETS
    assert set(body["engines"]) == constants.SUPPORTED_ENGINES
    assert set(body["evaluators"]) == constants.SUPPORTED_EVALUATORS
    assert set(body["profiles"]) == constants.SUPPORTED_PROFILES
    assert set(body["evidence_levels"]) == constants.SUPPORTED_EVIDENCE_LEVELS
    assert body["profile_defaults"] == constants.RUN_PROFILE_DEFAULTS
    assert body["policy_profiles"] == ["mitre_atlas", "owasp_agentic", "owasp_llm"]
    assert body["severity_levels"] == ["critical", "high", "medium", "low", "info"]
    assert body["default_profile"] == constants.DEFAULT_RUN_PROFILE
    assert capabilities()["targets"] == body["targets"]


def test_templates_list_only_run_specs_with_smoke_vs_real_badge(client: TestClient):
    listing = client.get("/v1/templates")
    assert listing.status_code == 200
    rows = {row["name"]: row for row in listing.json()}
    assert set(rows) == {"run_spec.smoke.yaml", "run_spec.mcs_real.sample.yaml"}
    assert rows["run_spec.smoke.yaml"]["kind"] == "smoke"
    assert rows["run_spec.smoke.yaml"]["spec_kind"] == "smoke"
    assert rows["run_spec.smoke.yaml"]["description"] == "launcher presence only"
    assert rows["run_spec.mcs_real.sample.yaml"]["kind"] == "real"
    assert rows["run_spec.mcs_real.sample.yaml"]["spec_kind"] is None
    assert rows["run_spec.mcs_real.sample.yaml"]["run_profile"] == "nightly"

    one = client.get("/v1/templates/run_spec.mcs_real.sample.yaml")
    assert one.status_code == 200
    assert one.json()["yaml"].startswith("name: mcs-real")
    assert client.get("/v1/templates/gateway_config.sample.yaml").status_code == 404
    assert client.get("/v1/templates/..%2Fpyproject.toml").status_code in {400, 404}
    assert client.get("/v1/templates/nope.yaml").status_code == 404


def test_validate_returns_errors_redacted_spec_defaults_and_env_status(client: TestClient):
    good = client.post("/v1/specs/validate", json={"spec": _spec()})
    assert good.status_code == 200
    body = good.json()
    assert body["ok"] is True and body["errors"] == []
    assert body["profile_defaults"] == constants.RUN_PROFILE_DEFAULTS["pr_gate"]
    assert body["resolved_spec"]["budget"]["max_duration_seconds"] == 900
    assert body["env_vars"] == [{"name": "REDPLANE_TEST_TOKEN", "set": True}]
    assert SECRET not in good.text
    assert body["resolved_spec"]["targets"][0]["auth"]["headers"]["Authorization"] == "***REDACTED***"
    assert body["spec_kind"] is None

    # YAML body, unset variable, structural error: one round trip reports all of it.
    yaml_text = (
        "name: ''\nrun_profile: nightly\ntargets:\n  - id: a\n    type: http\n    endpoint: http://x\n"
        "    auth: {api_key: '${REDPLANE_UNSET_TOKEN}'}\nengines: []\n"
    )
    bad = client.post("/v1/specs/validate", json={"yaml": yaml_text})
    assert bad.status_code == 200
    body = bad.json()
    assert body["ok"] is False
    assert any("name is required" in err for err in body["errors"])
    assert body["env_vars"] == [{"name": "REDPLANE_UNSET_TOKEN", "set": False}]
    assert body["resolved_spec"] is None

    # Literal credential in an auth field is refused by the builder even though the spec parses.
    literal = client.post("/v1/specs/validate", json={"spec": _spec(auth={"api_key": SECRET})})
    body = literal.json()
    assert body["ok"] is False
    assert any("targets[0].auth.api_key" in err and "${VAR}" in err for err in body["errors"])
    assert SECRET not in literal.text

    assert client.post("/v1/specs/validate", json={"yaml": "- just\n- a list\n"}).json()["ok"] is False
    assert client.post("/v1/specs/validate", json={"yaml": "a: [unclosed"}).json()["ok"] is False
    assert client.post("/v1/specs/validate", json={}).status_code == 400
    assert client.post("/v1/specs/validate", json={"yaml": "x" * (300 * 1024)}).status_code == 413


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s["targets"][0].__setitem__("type", "${REDPLANE_TEST_TOKEN}"),
        lambda s: s["engines"][0].__setitem__("name", "${REDPLANE_TEST_TOKEN}"),
        lambda s: s.__setitem__("evaluators", [{"name": "${REDPLANE_TEST_TOKEN}"}]),
        lambda s: s.__setitem__("run_profile", "${REDPLANE_TEST_TOKEN}"),
        lambda s: s.__setitem__("evidence_level", "${REDPLANE_TEST_TOKEN}"),
        lambda s: s.__setitem__("seed", "${REDPLANE_TEST_TOKEN}"),
    ],
    ids=["target_type", "engine_name", "evaluator_name", "run_profile", "evidence_level", "seed"],
)
def test_validate_errors_never_echo_an_expanded_variable_value(client: TestClient, mutate):
    """M1: enum validators lower-case and echo the offending value; a `${VAR}` there must
    surface as the token, never as the environment value (in any letter case)."""
    spec = _spec()
    mutate(spec)
    response = client.post("/v1/specs/validate", json={"spec": spec})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False and body["errors"]
    assert SECRET.lower() not in response.text.lower()
    assert body["resolved_spec"] is None
    assert body["env_vars"] == [{"name": "REDPLANE_TEST_TOKEN", "set": True}]

    token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/ui/specs").text).group(1)
    import yaml

    page = client.post("/ui/specs/validate", data={"yaml": yaml.safe_dump(spec), "csrf_token": token})
    assert page.status_code == 200
    assert "Validation failed" in page.text
    assert SECRET.lower() not in page.text.lower()


def test_validate_keeps_working_when_a_variable_is_used_legitimately_in_a_numeric_field(client: TestClient, monkeypatch):
    monkeypatch.setenv("REDPLANE_SEED", "4242")
    spec = _spec(seed="${REDPLANE_SEED}")
    body = client.post("/v1/specs/validate", json={"spec": spec}).json()
    assert body["ok"] is True
    assert body["resolved_spec"]["seed"] == 4242  # short, non-secret numeric values are not scrubbed
    assert body["env_vars"] == [{"name": "REDPLANE_SEED", "set": True}, {"name": "REDPLANE_TEST_TOKEN", "set": True}]


def test_yaml_aliases_are_rejected_instead_of_expanded(client: TestClient):
    """Alias bombs bypass the byte cap (a 467-byte document expanded for 34 s of CPU).
    RunSpecs have no use for anchors/aliases, so the loader refuses them outright."""
    import time

    levels = ["a0: &a0 [x, x, x, x, x, x, x, x, x]"]
    for depth in range(1, 9):
        levels.append(f"a{depth}: &a{depth} [" + ", ".join(f"*a{depth - 1}" for _ in range(9)) + "]")
    bomb = "\n".join(levels) + "\n"
    assert len(bomb.encode()) < 1024

    started = time.perf_counter()
    response = client.post("/v1/specs/validate", json={"yaml": bomb})
    assert time.perf_counter() - started < 2.0
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert any("alias" in err.lower() for err in body["errors"])

    # A plain anchor without reuse is refused the same way (no special cases to reason about).
    anchored = client.post("/v1/specs/validate", json={"yaml": "name: &n x\nrun_profile: *n\n"}).json()
    assert anchored["ok"] is False and any("alias" in err.lower() for err in anchored["errors"])

    token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/ui/specs").text).group(1)
    started = time.perf_counter()
    page = client.post("/ui/specs/load", data={"yaml": bomb, "csrf_token": token})
    assert time.perf_counter() - started < 2.0
    assert page.status_code == 400
    assert "alias" in page.text.lower()


def test_probe_runs_healthchecks_and_never_echoes_secrets(client: TestClient):
    skipped = client.post("/v1/specs/probe", json={"spec": _spec()})
    assert skipped.status_code == 200
    body = skipped.json()
    assert body["ok"] is True
    assert body["targets"][0]["target_id"] == "agent" and body["targets"][0]["ok"] is True
    assert SECRET not in skipped.text

    spec = _spec()
    spec["targets"][0]["config"] = {"skip_healthcheck": False, "timeout_seconds": 1}
    spec["targets"][0]["endpoint"] = "http://127.0.0.1:9/invoke"  # nothing listens there
    failing = client.post("/v1/specs/probe", json={"spec": spec})
    assert failing.status_code == 200
    assert failing.json()["ok"] is False
    assert failing.json()["targets"][0]["ok"] is False
    assert SECRET not in failing.text

    invalid = client.post("/v1/specs/probe", json={"spec": {"name": "x"}})
    assert invalid.status_code == 400


def test_form_and_yaml_round_trip():
    payload = _spec(evaluators=[{"name": "deepeval", "metrics": ["toxicity"], "params": {"threshold": 0.5}}])
    form = payload_to_form(payload)
    assert form["name"] == "builder-spec"
    assert form["target_auth_mode"] == "bearer" and form["target_auth_var"] == "REDPLANE_TEST_TOKEN"
    assert form["engine_garak"] == "on" and form["engine_garak_command"] == "garak --version"
    assert form["evaluator_deepeval"] == "on"

    rebuilt = form_to_payload(form)
    assert rebuilt["targets"][0]["auth"] == {"headers": {"Authorization": "Bearer ${REDPLANE_TEST_TOKEN}"}}
    assert rebuilt["engines"] == [{"name": "garak", "params": {"command": "garak --version"}}]
    assert [e["name"] for e in rebuilt["evaluators"]] == ["deepeval"]
    assert validate_spec_payload(rebuilt).ok is True
    assert payload_to_form(rebuilt) == form


def test_ui_specs_page_builds_validates_and_probes_without_revealing_values(client: TestClient):
    page = client.get("/ui/specs")
    assert page.status_code == 200
    assert 'name="yaml"' in page.text
    assert "run_spec.smoke.yaml" in page.text and 'class="badge kind">smoke' in page.text
    assert 'class="badge fail">real' in page.text
    for engine in sorted(constants.SUPPORTED_ENGINES):
        assert f'name="engine_{engine}"' in page.text
    assert "Run" not in re.findall(r"<button[^>]*>([^<]*)</button>", page.text)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)

    from_template = client.get("/ui/specs", params={"template": "run_spec.mcs_real.sample.yaml"})
    assert "name: mcs-real" in from_template.text
    assert client.get("/ui/specs", params={"template": "nope.yaml"}).status_code == 404

    # Form -> YAML
    form = payload_to_form(_spec())
    built = client.post("/ui/specs/build", data={**form, "csrf_token": token})
    assert built.status_code == 200
    assert "Authorization: Bearer ${REDPLANE_TEST_TOKEN}" in built.text
    assert SECRET not in built.text

    # YAML -> form
    yaml_text = re.search(r'<textarea[^>]*name="yaml"[^>]*>(.*?)</textarea>', built.text, flags=re.S).group(1)
    loaded = client.post("/ui/specs/load", data={"yaml": yaml_text, "csrf_token": token})
    assert loaded.status_code == 200
    assert 'name="target_auth_var" value="REDPLANE_TEST_TOKEN"' in loaded.text

    # Validate: errors inline, redacted resolved spec, profile defaults, env status as booleans.
    validated = client.post("/ui/specs/validate", data={"yaml": yaml_text, "csrf_token": token})
    assert validated.status_code == 200
    assert "Validation OK" in validated.text
    assert "REDPLANE_TEST_TOKEN" in validated.text and "set" in validated.text
    assert SECRET not in validated.text
    assert "***REDACTED***" in validated.text
    assert "max_duration_seconds" in validated.text

    broken = client.post("/ui/specs/validate", data={"yaml": "name: ''\n", "csrf_token": token})
    assert "name is required" in broken.text

    probed = client.post("/ui/specs/probe", data={"yaml": yaml_text, "csrf_token": token})
    assert probed.status_code == 200
    assert "skip_healthcheck" in probed.text or "ok" in probed.text
    assert SECRET not in probed.text

    assert client.post("/ui/specs/validate", data={"yaml": yaml_text}).status_code == 403
