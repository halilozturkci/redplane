import re

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

    assert payload not in html
    assert "<img" not in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<target>" not in html and "&lt;target&gt;" in html
    assert "<engine>" not in html and "&lt;engine&gt;" in html
    assert "<category>" not in html and "&lt;category&gt;" in html
    assert "<td>&lt;metric&gt;</td>" in html
    assert "run-&lt;b&gt;id&lt;/b&gt;" in html
    assert "<b>id</b>" not in html
    # Defense in depth for a file that gets emailed: only the viewer's own inline
    # script and stylesheet (pinned by sha256) may run, nothing injected can.
    csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)
    assert csp.startswith("default-src 'none'; script-src 'sha256-")
    assert "'unsafe-inline'" not in csp
    # The only executable script is the viewer; attacker text never reaches a script context.
    assert len(re.findall(r"<script>", html)) == 1
