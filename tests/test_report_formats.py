from urt.report import render_csv, render_html, render_markdown


def test_report_formats_render():
    scorecard = {
        "run_id": "r1",
        "total_findings": 2,
        "asr_overall": 0.1,
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "info": 0,
    }
    findings = [
        {
            "finding_id": "f1",
            "run_id": "r1",
            "target_id": "t1",
            "engine": "pyrit",
            "severity": "high",
            "category": "prompt_injection",
            "sub_category": "x",
            "attack_vector": "jailbreak",
            "attack_complexity": "difficult",
            "success": True,
            "description": "attack succeeded",
        },
        {
            "finding_id": "f2",
            "run_id": "r1",
            "target_id": "t1",
            "engine": "garak",
            "severity": "medium",
            "category": "robustness",
            "sub_category": "y",
            "attack_vector": "probe",
            "attack_complexity": "easy",
            "success": False,
            "description": "blocked",
        },
    ]

    md = render_markdown(scorecard, findings)
    html = render_html(scorecard, findings)
    csv_text = render_csv(findings)

    assert "URT Report" in md
    assert "<html" in html.lower()
    assert "finding_id,run_id,target_id" in csv_text
