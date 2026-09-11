from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

CANDIDATE_KEYS = (
    "prompt",
    "input",
    "question",
    "attack_prompt",
    "goal",
    "instruction",
    "text",
)


def _extract_prompt(record: dict) -> str | None:
    for key in CANDIDATE_KEYS:
        value = record.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _read_json(path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    prompts: list[str] = []

    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, str) and item.strip():
                prompts.append(item.strip())
            elif isinstance(item, dict):
                extracted = _extract_prompt(item)
                if extracted:
                    prompts.append(extracted)
        return prompts

    if isinstance(payload, dict):
        for key in ("prompts", "data", "records", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        prompts.append(item.strip())
                    elif isinstance(item, dict):
                        extracted = _extract_prompt(item)
                        if extracted:
                            prompts.append(extracted)
                return prompts

    return prompts


def _read_jsonl(path: Path) -> list[str]:
    prompts: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        if isinstance(item, dict):
            extracted = _extract_prompt(item)
            if extracted:
                prompts.append(extracted)
    return prompts


def _read_csv(path: Path) -> list[str]:
    prompts: list[str] = []
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            extracted = _extract_prompt(row)
            if extracted:
                prompts.append(extracted)
    return prompts


def main() -> int:
    parser = argparse.ArgumentParser(description="Build DEEPTEAM_SEED_DATASET JSON from open datasets")
    parser.add_argument("--input", required=True, help="Input dataset file (.json/.jsonl/.csv)")
    parser.add_argument("--output", required=True, help="Output JSON file with {\"prompts\": [...]} shape")
    parser.add_argument("--max-prompts", type=int, default=200)
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    if not input_path.exists():
        raise SystemExit(f"input file not found: {input_path}")

    suffix = input_path.suffix.lower()
    if suffix == ".json":
        prompts = _read_json(input_path)
    elif suffix == ".jsonl":
        prompts = _read_jsonl(input_path)
    elif suffix == ".csv":
        prompts = _read_csv(input_path)
    else:
        raise SystemExit("unsupported format; use .json, .jsonl, or .csv")

    seen: set[str] = set()
    deduped: list[str] = []
    for prompt in prompts:
        normalized = " ".join(prompt.split())
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
        if len(deduped) >= max(args.max_prompts, 1):
            break

    payload = {"prompts": deduped}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {output_path} prompts={len(deduped)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
