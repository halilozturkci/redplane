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


def test_render_html_escapes_attacker_controlled_text():
    payload = "<script>alert('xss')</script><img src=x onerror=alert(1)>"
    scorecard = {
        "run_id": "run-<b>id</b>",
        "total_findings": 1,
        "asr_overall": 0.0,
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
        "eval_scores": {"<metric>": 0.5},
        "eval_pass_rate": 0.5,
    }
    findings = [
        {
            "finding_id": "f1",
            "run_id": "r1",
            "target_id": "<target>",
            "engine": "<engine>",
            "severity": "high",
            "category": "<category>",
            "description": payload,
        }
    ]

    html = render_html(scorecard, findings)

    assert "<script>" not in html
    assert "<img" not in html
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<td>&lt;target&gt;</td>" in html
    assert "<td>&lt;engine&gt;</td>" in html
    assert "<td>&lt;category&gt;</td>" in html
    assert "<td>&lt;metric&gt;</td>" in html
    assert "run-&lt;b&gt;id&lt;/b&gt;" in html
    assert "<b>id</b>" not in html
    # Defense in depth for a file that gets emailed: no scripts can run even if a
    # future interpolation site forgets to escape.
    assert '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'" />' in html
