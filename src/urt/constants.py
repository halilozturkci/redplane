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

# 1.0: initial bundle. 1.1: target auth and sensitive keys are redacted and known
# secret values (`${VAR}` substitutions, credential values) are scrubbed from
# every file the run writes.
BUNDLE_FORMAT_VERSION = "1.1"
# Oldest bundle version whose spec-bearing files may be served raw.
REDACTED_BUNDLE_MIN_VERSION = "1.1"
# The only files a pre-1.1 bundle may serve raw: aggregates and rendered reports.
# Everything else (spec, manifest, findings, summaries, sidecars, raw tool logs)
# may hold expanded credentials.
LEGACY_RAW_DOWNLOAD_ALLOWLIST = ("scorecard.json", "artifacts_index.json", "report.md", "report.html", "report.csv")

# Secret values shorter than this are not value-scrubbed (too likely to collide with
# ordinary words); they are still masked by key/position rules.
MIN_SECRET_LENGTH = 8

# How bundle files are served (API artifact routes and `urt view`). Text-like
# files are served inline with a fixed media type; everything else (HTML, binaries,
# unknown suffixes) is an attachment so the browser never renders attacker-influenced
# tool output in the serving origin.
ARTIFACT_INLINE_MEDIA_TYPES = {
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".md": "text/markdown; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".yaml": "text/plain; charset=utf-8",
    ".yml": "text/plain; charset=utf-8",
}
ARTIFACT_ATTACHMENT_MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
}
ARTIFACT_RESPONSE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    # Artifacts are attacker-influenced tool output; never let them script or be
    # cached if a UI is served from this origin.
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Cache-Control": "no-store",
}

# Pre-filled expiry when a waiver is created from the UI (§4.6: "+30 days").
WAIVER_DEFAULT_EXPIRY_DAYS = 30

# Per-finding cap on the pretty-printed `metadata` JSON embedded in report.html.
# Larger payloads are truncated with a link to the raw artifact.
REPORT_METADATA_JSON_CAP = 4096

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
