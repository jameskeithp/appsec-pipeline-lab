"""Unit tests for tools/gate.py -- the pipeline's policy logic."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.gate import (
    Finding,
    evaluate,
    findings_from_pip_audit,
    findings_from_sarif,
    main,
    normalize_severity,
)


def test_normalize_severity_known_and_unknown():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("error") == "high"
    assert normalize_severity("warning") == "medium"
    assert normalize_severity(None) == "medium"
    assert normalize_severity("something-new") == "medium"


def _sarif(level="error", severity=None):
    rule = {"id": "py/test-rule", "defaultConfiguration": {"level": "note"}}
    if severity:
        rule["properties"] = {"severity": severity}
    return {
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": [rule]}},
                "results": [
                    {
                        "ruleId": "py/test-rule",
                        "level": level,
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/app.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }


def test_sarif_parsing_maps_level_and_location():
    findings = findings_from_sarif(_sarif())
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.severity == "high"
    assert f.location == "app/app.py:42"


def test_sarif_falls_back_to_rule_default_level():
    data = _sarif()
    data["runs"][0]["results"][0].pop("level")
    data["runs"][0]["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {
        "level": "error"
    }
    findings = findings_from_sarif(data)
    assert findings[0].severity == "high"


def test_pip_audit_parsing_marks_vulns_high():
    data = {
        "dependencies": [
            {
                "name": "werkzeug",
                "version": "2.2.3",
                "vulns": [{"id": "CVE-2023-25577"}],
            },
            {"name": "flask", "version": "2.2.3", "vulns": []},
        ]
    }
    findings = findings_from_pip_audit(data)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule_id == "CVE-2023-25577"


def test_pip_audit_dedupes_repeated_advisories():
    data = {
        "dependencies": [
            {
                "name": "werkzeug",
                "version": "2.2.3",
                "vulns": [{"id": "CVE-2023-25577"}, {"id": "CVE-2023-25577"}],
            }
        ]
    }
    assert len(findings_from_pip_audit(data)) == 1


def test_evaluate_blocks_at_and_above_threshold():
    findings = [
        Finding("semgrep", "r1", "critical", "a.py:1"),
        Finding("semgrep", "r2", "medium", "a.py:2"),
    ]
    passed, blocking = evaluate(findings, threshold="high")
    assert not passed
    assert [f.rule_id for f in blocking] == ["r1"]


def test_evaluate_baseline_suppresses_known_findings():
    findings = [Finding("semgrep", "r1", "critical", "a.py:1")]
    passed, blocking = evaluate(
        findings, threshold="high", baseline_keys={"semgrep|r1|a.py:1"}
    )
    assert passed
    assert blocking == []


def test_main_fails_closed_on_missing_file(tmp_path):
    assert main(["--sarif", str(tmp_path / "nope.sarif")]) == 2


def test_main_end_to_end(tmp_path):
    sarif_path = tmp_path / "out.sarif"
    sarif_path.write_text(json.dumps(_sarif()), encoding="utf-8")
    assert main(["--sarif", str(sarif_path)]) == 1  # high finding blocks
    assert main(["--sarif", str(sarif_path), "--threshold", "critical"]) == 0
