"""URT command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from .config import dump_run_spec, load_run_spec
from .constants import DEFAULT_ARTIFACT_ROOT, DEFAULT_METADATA_DB
from .engine_pins import pin
from .powercat_kit import DEFAULT_COMMAND
from .orchestrator import Orchestrator
from .redaction import Scrubber, redact_run_spec_payload, redact_target_payload
from .storage.artifact_store import ArtifactPathError, ArtifactStore
from .report import (
    GateResult,
    gate_result,
    load_findings,
    parse_eval_min_pass_rate,
    render_csv,
    render_markdown,
    scorecard_eval_pass_rate,
)
from .gateway import load_gateway_config, serve_gateway
from .gateway.config import GatewayConfigError
from .gateway.redaction import redact_payload
from .ui import load_bundle
from .ui.render import render_run_page
from .ui.view_server import LoopbackOnlyError, build_view_server, is_loopback_host


def _template_payload() -> dict[str, Any]:
    """Launcher-presence smoke spec. Real attacks live in per-engine sample YAMLs."""
    return {
        "name": "foundry-copilot-smoke",
        "run_profile": "nightly",
        "metadata": {
            "spec_kind": "smoke",
            "description": "Launcher presence only. Not an assessment. See templates/run_spec.mcs_real.sample.yaml and other *.sample.yaml files for real runs.",
        },
        "targets": [
            {
                "id": "copilot-prod",
                "type": "copilot",
                "endpoint": "https://your-copilot-endpoint/api/chat",
                "auth": {"headers": {"Authorization": "Bearer <token>"}},
                "config": {"mode": "http", "skip_healthcheck": True},
            },
            {
                "id": "foundry-agent",
                "type": "foundry",
                "endpoint": "https://your-foundry-endpoint/api/chat",
                "auth": {"api_key": "<key>"},
                "config": {"skip_healthcheck": True},
            },
            {
                "id": "generic-agent",
                "type": "http",
                "endpoint": "http://localhost:8080/invoke",
                "config": {
                    "skip_healthcheck": True,
                    "timeout_seconds": 60,
                    "retry_attempts": 2,
                    "retry_backoff_seconds": 1.0,
                    "retry_on_status": [429, 500, 502, 503, 504],
                },
            },
        ],
        "engines": [
            {
                "name": "pyrit",
                "params": {
                    "command": 'python -c "import pyrit; print(\'pyrit-ok\')"',
                },
            },
            {"name": "promptfoo", "params": {"command": "promptfoo --version"}},
            {"name": "garak", "params": {"command": pin("garak").uvx_command}},
            {
                "name": "powerpwn",
                "params": {
                    "mode": "recon-only",
                    "command": pin("powerpwn").uvx_command,
                },
            },
            {"name": "powercat", "params": {"command": DEFAULT_COMMAND}},
            {"name": "deepteam", "params": {"command": pin("deepteam").uvx_command}},
            {"name": "inspect", "params": {"command": pin("inspect-ai").uvx_command}},
            {
                "name": "giskard",
                "params": {"command": pin("giskard").uvx_command},
            },
        ],
        "evaluators": [
            {
                "name": "deepeval",
                "metrics": ["answer_relevancy", "faithfulness", "toxicity"],
                "params": {"command": pin("deepeval").uvx_command, "threshold": 0.5},
                "fail_open": True,
            },
            {
                "name": "promptfoo_eval",
                "params": {"command": "promptfoo --version", "threshold": 0.5},
                "fail_open": True,
            },
            {
                "name": "giskard_eval",
                "params": {"command": pin("giskard").uvx_command, "threshold": 0.5},
                "fail_open": True,
            },
            {
                "name": "inspect_eval",
                "params": {"command": "inspect --help", "threshold": 0.5},
                "fail_open": True,
            },
            {
                "name": "azure_ai_eval",
                "params": {"command": "python --version", "threshold": 0.5},
                "fail_open": True,
            },
            {
                "name": "custom_script",
                "params": {"command": "python --version", "threshold": 0.5},
                "fail_open": True,
            },
        ],
        "policy_profiles": ["owasp_llm", "owasp_agentic", "mitre_atlas"],
        "budget": {"max_duration_seconds": 3600},
        "timeouts": {"connect_seconds": 10, "request_seconds": 60, "engine_seconds": 1800},
        "evidence_level": "standard",
        "seed": 42,
    }


def _orchestrator(args: argparse.Namespace) -> Orchestrator:
    return Orchestrator(
        artifact_root=args.artifact_root,
        metadata_db=args.metadata_db,
    )


def cmd_init(args: argparse.Namespace) -> int:
    payload = _template_payload()
    dump_run_spec(args.output, payload)
    print(f"Created smoke run spec at {args.output}")
    print(
        "This is launcher presence only. For real attacks use "
        "templates/run_spec.mcs_real.sample.yaml, "
        "templates/run_spec.promptfoo_dataset.sample.yaml, "
        "templates/run_spec.deepteam_seeded.sample.yaml, "
        "templates/run_spec.promptfoo_gateway.sample.yaml, or "
        "templates/run_spec.eval_after_attack.sample.yaml."
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    spec = load_run_spec(args.spec)
    printable = Scrubber.from_spec(spec).scrub(redact_run_spec_payload(spec.to_dict()))
    print(json.dumps(printable, indent=2, ensure_ascii=False))
    print("Validation OK")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    spec = load_run_spec(args.spec)
    orchestrator = _orchestrator(args)
    result = orchestrator.execute(spec)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("status") == "completed" else 1


def cmd_report(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    run = orchestrator.get_run(args.run_id)
    if not run:
        print(f"Run not found: {args.run_id}", file=sys.stderr)
        return 1

    run_dir = orchestrator.artifact_store.existing_run_dir(args.run_id)
    if run_dir is None:
        print(f"Run directory not found for {args.run_id}", file=sys.stderr)
        return 1

    if args.in_place:
        # Works for failed runs too: the viewer renders the manifest error and
        # run_error.log head when there is no scorecard.
        orchestrator.write_reports(args.run_id)
        print(f"Report bundle refreshed in {run_dir}")
        return 0

    scorecard_path = run.get("scorecard_path")
    findings_path = run.get("findings_path")
    if not scorecard_path or not findings_path:
        print("Run does not contain scorecard/findings paths yet; use --in-place for failed runs", file=sys.stderr)
        return 1

    scorecard = json.loads(Path(scorecard_path).read_text(encoding="utf-8"))
    findings = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    markdown = render_markdown(scorecard, findings)
    # The viewer embeds the redacted bundle and the waivers stored right now.
    html = render_run_page(load_bundle(run_dir, waivers=orchestrator.list_waivers()), mode="static")
    csv_text = render_csv(findings)

    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        md_path = output_dir / "report.md"
        html_path = output_dir / "report.html"
        csv_path = output_dir / "report.csv"
        md_path.write_text(markdown, encoding="utf-8")
        html_path.write_text(html, encoding="utf-8")
        csv_path.write_text(csv_text, encoding="utf-8")
        print(f"Report bundle written to {output_dir}")
        if output_dir.resolve() != run_dir.resolve():
            print(
                "Note: evidence and file links in report.html are relative to the run directory "
                f"({run_dir}); copy the report there, use --in-place, or open it with `urt view`."
            )
        return 0

    if args.format == "md":
        content = markdown
    elif args.format == "html":
        content = html
    else:
        content = csv_text

    if args.output:
        Path(args.output).write_text(content, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(content)
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    run = orchestrator.get_run(args.run_id)
    if not run:
        print(f"Run not found: {args.run_id}", file=sys.stderr)
        return 1

    findings_path = run.get("findings_path")
    if not findings_path:
        print("Run does not contain findings path", file=sys.stderr)
        return 1

    findings = load_findings(findings_path)
    waivers: list[dict[str, Any]] = []
    if not args.ignore_waivers:
        waivers = orchestrator.list_waivers()
    result = gate_result(
        findings,
        threshold=args.threshold,
        waivers=waivers,
        eval_min_pass_rate=args.eval_min_pass_rate,
        eval_pass_rate=scorecard_eval_pass_rate(orchestrator.artifact_store.read_json(args.run_id, "scorecard.json")),
    )
    print(result.message)
    if args.explain:
        _print_gate_explanation(result)
    return 0 if result.ok else 2


def _print_gate_explanation(result: GateResult) -> None:
    print(f"Blocking findings ({len(result.blocking)}):")
    for row in result.blocking:
        print(
            f"  - [{str(row['severity']).upper()}] {row['finding_id']} "
            f"target={row['target_id']} engine={row['engine']} category={row['category']}"
        )
    print(f"Waived findings ({len(result.waived)}):")
    for row in result.waived:
        print(
            f"  - [{str(row['severity']).upper()}] {row['finding_id']} "
            f"waiver={row['waiver_id']} control={row['control_id']} "
            f"owner={row['owner']} expires={row['expires_at']}"
        )


def cmd_runs(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    print(json.dumps(orchestrator.list_runs(), indent=2, ensure_ascii=False))
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    print(json.dumps(orchestrator.get_findings(args.run_id), indent=2, ensure_ascii=False))
    return 0


def cmd_artifacts(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    print(json.dumps(orchestrator.list_artifacts(args.run_id), indent=2, ensure_ascii=False))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    spec = load_run_spec(args.spec)
    from .adapters import create_target_adapter

    rows: list[dict[str, Any]] = []
    exit_code = 0
    for target in spec.targets:
        adapter = create_target_adapter(target)
        adapter.apply_runtime(
            connect_seconds=spec.timeouts.connect_seconds,
            request_seconds=spec.timeouts.request_seconds,
        )
        ok, detail = adapter.healthcheck()
        rows.append(
            {
                "target_id": target.target_id,
                "type": target.target_type,
                "ok": ok,
                "detail": detail,
            }
        )
        if not ok:
            exit_code = 2

    print(json.dumps(Scrubber.from_spec(spec).scrub(rows), indent=2, ensure_ascii=False))
    return exit_code


def cmd_waivers_list(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    print(json.dumps(orchestrator.list_waivers(args.target_id), indent=2, ensure_ascii=False))
    return 0


def cmd_waivers_create(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    payload = {
        "waiver_id": args.waiver_id or str(uuid.uuid4()),
        "target_id": args.target_id,
        "control_id": args.control_id,
        "reason": args.reason,
        "owner": args.owner,
        "expires_at": args.expires_at,
    }
    created = orchestrator.create_waiver(payload)
    print(json.dumps(created, indent=2, ensure_ascii=False))
    return 0


def cmd_waivers_revoke(args: argparse.Namespace) -> int:
    orchestrator = _orchestrator(args)
    row = orchestrator.revoke_waiver(args.waiver_id, note=args.note)
    if row is None:
        print(f"Waiver not found: {args.waiver_id}", file=sys.stderr)
        return 1
    print(json.dumps(row, indent=2, ensure_ascii=False))
    return 0


def _serve_view(server) -> None:
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def cmd_view(args: argparse.Namespace) -> int:
    # Same run-id rules the server applies to every request (no separators, no "..").
    try:
        run_dir = ArtifactStore(args.artifact_root).existing_run_dir(args.run_id)
    except ArtifactPathError:
        run_dir = None
    if run_dir is None:
        print(f"Run directory not found: {Path(args.artifact_root) / args.run_id}", file=sys.stderr)
        return 1
    try:
        server = build_view_server(run_dir, host=args.host, port=args.port)
    except LoopbackOnlyError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    host, port = server.server_address[0], server.server_address[1]
    shown_host = f"[{host}]" if ":" in str(host) else host
    print(f"Serving {args.run_id} from {run_dir}")
    print(f"Open http://{shown_host}:{port}/  (Ctrl+C to stop)")
    _serve_view(server)
    return 0


def cmd_serve_api(args: argparse.Namespace) -> int:
    if not is_loopback_host(args.host) and not args.unsafe_allow_non_loopback:
        print(
            f"Error: refusing to bind {args.host!r}. The API and /ui have no authentication; they are "
            "meant for one operator on one machine. Bind a loopback address (default 127.0.0.1) and use "
            "an SSH tunnel, or pass --unsafe-allow-non-loopback if you accept exposing runs, findings "
            "and artifacts to that network.",
            file=sys.stderr,
        )
        return 2
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required for API serving. Install dependencies first.", file=sys.stderr)
        return 1

    uvicorn.run(
        "urt.api:create_app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        factory=True,
    )
    return 0


def cmd_serve_gateway(args: argparse.Namespace) -> int:
    try:
        config = load_gateway_config(args.config)
    except (GatewayConfigError, FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.host:
        config.gateway.host = str(args.host)
    if args.port is not None:
        config.gateway.port = int(args.port)

    if args.print_effective_config:
        printable = config.to_dict()
        # Same rule as run specs: every auth leaf is a credential, whatever its key.
        printable["targets"] = {
            target_id: redact_target_payload(target) for target_id, target in printable.get("targets", {}).items()
        }
        print(json.dumps(redact_payload(printable), indent=2, ensure_ascii=False))

    serve_gateway(config)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Redplane CLI (urt) — attack and evaluation control plane"
    )
    parser.add_argument("--artifact-root", default=DEFAULT_ARTIFACT_ROOT, help="Artifact output directory")
    parser.add_argument("--metadata-db", default=DEFAULT_METADATA_DB, help="Metadata sqlite path")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a smoke run spec (launcher presence only)")
    p_init.add_argument("--output", default="run_spec.yaml", help="Output run spec path")
    p_init.add_argument(
        "--smoke",
        action="store_true",
        help="Write a launcher-presence smoke spec (this is the default)",
    )
    p_init.set_defaults(func=cmd_init)

    p_validate = sub.add_parser("validate", help="Validate a run spec")
    p_validate.add_argument("--spec", required=True, help="Run spec (.yaml/.json)")
    p_validate.set_defaults(func=cmd_validate)

    p_run = sub.add_parser("run", help="Execute run spec")
    p_run.add_argument("--spec", required=True, help="Run spec (.yaml/.json)")
    p_run.set_defaults(func=cmd_run)

    p_report = sub.add_parser("report", help="Generate report for run")
    p_report.add_argument("--run-id", required=True, help="Run ID")
    p_report.add_argument("--output", help="Output report file")
    p_report.add_argument("--format", default="md", choices=["md", "html", "csv"])
    p_report.add_argument("--output-dir", help="Write report bundle (md/html/csv) into directory")
    p_report.add_argument(
        "--in-place",
        action="store_true",
        help="Re-render report.md/html/csv inside the run directory and rebuild artifacts_index.json "
        "(refreshes the waiver state embedded in report.html)",
    )
    p_report.set_defaults(func=cmd_report)

    p_gate = sub.add_parser("gate", help="Evaluate run against severity threshold")
    p_gate.add_argument("--run-id", required=True, help="Run ID")
    p_gate.add_argument("--threshold", default="high", choices=["critical", "high", "medium", "low", "info"])
    p_gate.add_argument(
        "--ignore-waivers",
        action="store_true",
        help="Ignore stored waivers when evaluating the gate",
    )
    p_gate.add_argument(
        "--explain",
        action="store_true",
        help="List the blocking findings and the waived findings with their waiver",
    )
    p_gate.add_argument(
        "--eval-min-pass-rate",
        type=parse_eval_min_pass_rate,
        default=None,
        metavar="0..1",
        help="Also fail the gate when the scorecard eval_pass_rate is below this fraction "
        "(fails when the run has no evaluator scores)",
    )
    p_gate.set_defaults(func=cmd_gate)

    p_runs = sub.add_parser("runs", help="List runs")
    p_runs.set_defaults(func=cmd_runs)

    p_findings = sub.add_parser("findings", help="List normalized findings for run")
    p_findings.add_argument("--run-id", required=True, help="Run ID")
    p_findings.set_defaults(func=cmd_findings)

    p_artifacts = sub.add_parser("artifacts", help="List artifacts for run")
    p_artifacts.add_argument("--run-id", required=True, help="Run ID")
    p_artifacts.set_defaults(func=cmd_artifacts)

    p_probe = sub.add_parser("probe", help="Probe targets in run spec via healthchecks")
    p_probe.add_argument("--spec", required=True, help="Run spec (.yaml/.json)")
    p_probe.set_defaults(func=cmd_probe)

    p_waivers = sub.add_parser("waivers", help="Create or list control waivers")
    waiver_sub = p_waivers.add_subparsers(dest="waivers_command", required=True)
    p_waivers_list = waiver_sub.add_parser("list", help="List waivers")
    p_waivers_list.add_argument("--target-id", help="Filter by target id")
    p_waivers_list.set_defaults(func=cmd_waivers_list)
    p_waivers_create = waiver_sub.add_parser("create", help="Create a waiver")
    p_waivers_create.add_argument("--target-id", required=True)
    p_waivers_create.add_argument("--control-id", required=True)
    p_waivers_create.add_argument("--reason", required=True)
    p_waivers_create.add_argument("--owner", required=True)
    p_waivers_create.add_argument("--expires-at", required=True, help="ISO-8601 expiry timestamp")
    p_waivers_create.add_argument("--waiver-id", help="Optional stable waiver id")
    p_waivers_create.set_defaults(func=cmd_waivers_create)
    p_waivers_revoke = waiver_sub.add_parser(
        "revoke", help="Revoke a waiver: set expires_at to now (the row and its history are kept)"
    )
    p_waivers_revoke.add_argument("--waiver-id", required=True)
    p_waivers_revoke.add_argument("--note", help="Optional note recorded with the revoke event")
    p_waivers_revoke.set_defaults(func=cmd_waivers_revoke)

    p_view = sub.add_parser(
        "view", help="Serve one run directory (report.html viewer + bundle files) on loopback"
    )
    p_view.add_argument("run_id", help="Run ID (directory name under --artifact-root)")
    p_view.add_argument("--host", default="127.0.0.1", help="Loopback address only (default 127.0.0.1)")
    p_view.add_argument("--port", type=int, default=8765, help="Port (0 picks a free port)")
    p_view.set_defaults(func=cmd_view)

    p_api = sub.add_parser("serve-api", help="Run REST API and the read-only /ui pages")
    p_api.add_argument("--host", default="127.0.0.1", help="Loopback by default; see --unsafe-allow-non-loopback")
    p_api.add_argument("--port", type=int, default=8000)
    p_api.add_argument("--reload", action="store_true")
    p_api.add_argument(
        "--unsafe-allow-non-loopback",
        action="store_true",
        help="Allow binding a non-loopback host. There is no authentication: anyone on that network "
        "can read every run, finding and artifact and submit runs.",
    )
    p_api.set_defaults(func=cmd_serve_api)

    p_gateway = sub.add_parser(
        "serve-gateway", help="Run the OpenAI-compatible network gateway"
    )
    p_gateway.add_argument("--config", required=True, help="Gateway config (.yaml/.yml/.json)")
    p_gateway.add_argument("--host", help="Override gateway host from config")
    p_gateway.add_argument("--port", type=int, help="Override gateway port from config")
    p_gateway.add_argument("--print-effective-config", action="store_true")
    p_gateway.set_defaults(func=cmd_serve_gateway)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
