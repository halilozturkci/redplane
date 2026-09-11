"""Shared constants for URT."""

DEFAULT_ARTIFACT_ROOT = ".urt_state/artifacts"
DEFAULT_METADATA_DB = ".urt_state/metadata/urt.sqlite3"
DEFAULT_RUN_PROFILE = "nightly"

SUPPORTED_TARGETS = {"foundry", "copilot", "http"}
SUPPORTED_ENGINES = {
    "pyrit",
    "promptfoo",
    "garak",
    "powerpwn",
    "powercat",
    "deepteam",
    "inspect",
    "giskard",
}
SUPPORTED_PROFILES = {"pr_gate", "nightly", "weekly_deep"}
SUPPORTED_EVIDENCE_LEVELS = {"minimal", "standard", "full"}

# Applied when RunSpec omits budget/timeouts. Explicit spec values always win.
RUN_PROFILE_DEFAULTS: dict[str, dict] = {
    "pr_gate": {
        "budget": {"max_duration_seconds": 900},
        "timeouts": {"connect_seconds": 5, "request_seconds": 30, "engine_seconds": 600},
        "gate_threshold": "high",
    },
    "nightly": {
        "budget": {"max_duration_seconds": 3600},
        "timeouts": {"connect_seconds": 10, "request_seconds": 60, "engine_seconds": 1800},
        "gate_threshold": "high",
    },
    "weekly_deep": {
        "budget": {"max_duration_seconds": 14400},
        "timeouts": {"connect_seconds": 15, "request_seconds": 120, "engine_seconds": 7200},
        "gate_threshold": "high",
    },
}

# Stdout/stderr artifact caps by evidence_level (`None` = unlimited).
EVIDENCE_TEXT_LIMITS: dict[str, int | None] = {
    "minimal": 8 * 1024,
    "standard": 256 * 1024,
    "full": None,
}

COST_METRIC_KEYS = ("cost_usd", "estimated_cost_usd")

SUPPORTED_EVALUATORS = {
    "deepeval",
    "promptfoo_eval",
    "giskard_eval",
    "inspect_eval",
    "azure_ai_eval",
    "custom_script",
}

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

AUDIT_BUNDLE_FILES = (
    "resolved_spec.json",
    "run_manifest.json",
    "engine_invocations.json",
    "artifacts_index.json",
    "findings.json",
    "scorecard.json",
    "run_summary.json",
    "report.md",
    "report.html",
    "report.csv",
)
