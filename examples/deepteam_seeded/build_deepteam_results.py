from __future__ import annotations

import argparse
import json
from pathlib import Path


def to_float(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize DeepTeam output for URT")
    parser.add_argument("--out-dir", default="/tmp/urt-real-attacks/deepteam_out")
    parser.add_argument("--output", default="/tmp/urt-real-attacks/deepteam_results.json")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    output = Path(args.output)

    candidates = sorted(out_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        output.write_text(json.dumps({"results": []}, indent=2), encoding="utf-8")
        print(f"wrote {output} results=0 (no deepteam output found)")
        return 0

    latest = candidates[0]
    payload = json.loads(latest.read_text(encoding="utf-8"))

    test_cases = payload.get("test_cases") or []
    overview = payload.get("overview") if isinstance(payload, dict) else {}
    results = []

    for case in test_cases:
        if not isinstance(case, dict):
            continue

        score = to_float(case.get("score"), 0.0)
        error = case.get("error")
        vuln = str(case.get("vulnerability") or "unknown")
        attack = str(case.get("attack_method") or "unknown")
        desc = str(case.get("reason") or "")
        if error:
            desc = f"DeepTeam error: {error}"

        results.append(
            {
                "vulnerability": vuln,
                "attack": attack,
                "score": score,
                "is_vulnerable": bool(score >= 0.5 and not error),
                "description": desc or f"DeepTeam result for {vuln}",
                "complexity": "unknown",
                "raw_case": case,
            }
        )

    normalized = {
        "results": results,
        "source": str(latest),
        "overview": overview if isinstance(overview, dict) else {},
    }
    output.write_text(json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {output} results={len(results)} source={latest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
