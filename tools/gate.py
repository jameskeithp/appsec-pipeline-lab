#!/usr/bin/env python3
"""Severity gate for the AppSec pipeline.

Reads scanner output (SARIF from Semgrep/CodeQL, JSON from pip-audit)
and answers one question: does this change introduce findings at or
above the blocking severity?

Policy (see docs/triage-and-slas.md for the full program policy):
  * Default blocking threshold: "high" -- any NEW finding whose
    normalized severity is high or critical fails the gate.
  * Findings already recorded in a baseline file do not block; that is
    how a team adopts gating on a legacy codebase without a flag day.
  * The gate fails closed on unreadable input: a scanner that produced
    garbage must never look like a scanner that produced nothing.

The module is deliberately small and dependency-free so it can be unit
tested anywhere (tests/test_gate.py) and dropped into any CI system.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

# Normalized severity ladder. Index = rank; higher is worse.
SEVERITY_ORDER = ["note", "low", "medium", "high", "critical"]

# SARIF levels and pip-audit do not share a vocabulary; map both onto
# the ladder above. Unknown values map to "medium" so they are seen by
# a human instead of silently dropped.
SARIF_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "note",
}


def normalize_severity(raw: str | None) -> str:
    if raw is None:
        return "medium"
    value = str(raw).strip().lower()
    if value in SEVERITY_ORDER:
        return value
    return SARIF_LEVEL_TO_SEVERITY.get(value, "medium")


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(normalize_severity(severity))


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: str
    location: str

    @property
    def key(self) -> str:
        """Stable identity used for baseline comparison."""
        return f"{self.tool}|{self.rule_id}|{self.location}"


def findings_from_sarif(data: dict, tool_fallback: str = "sarif") -> list[Finding]:
    findings: list[Finding] = []
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", tool_fallback)
        rules = {
            r.get("id"): r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown-rule")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {}) or {}
            raw = (
                props.get("severity")
                or result.get("properties", {}).get("severity")
                or result.get("level")
                # Semgrep SARIF carries the rule's original severity
                # (ERROR/WARNING/INFO) here when the result has no level.
                or rule.get("defaultConfiguration", {}).get("level")
            )
            location = "unknown"
            locations = result.get("locations", [])
            if locations:
                physical = locations[0].get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {}).get("uri", "")
                line = physical.get("region", {}).get("startLine", "")
                location = f"{artifact}:{line}" if artifact else "unknown"
            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    severity=normalize_severity(raw),
                    location=location,
                )
            )
    return findings


def findings_from_pip_audit(data: dict) -> list[Finding]:
    """pip-audit --format json emits {"dependencies": [...]}.

    pip-audit does not publish per-CVE severity in its JSON, so every
    known-vulnerable dependency is treated as "high": a dependency with
    a published fix available is exactly the class of finding the SCA
    stage exists to block on. Documented in docs/triage-and-slas.md.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            # pip-audit can repeat the same advisory for one package
            # (once per affected version range); count it once.
            dedupe_key = (dep.get("name", ""), vuln.get("id", ""))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(
                Finding(
                    tool="pip-audit",
                    rule_id=vuln.get("id", "unknown-cve"),
                    severity="high",
                    location=f"{dep.get('name')}=={dep.get('version')}",
                )
            )
    return findings


def evaluate(
    findings: list[Finding],
    threshold: str = "high",
    baseline_keys: set[str] | None = None,
) -> tuple[bool, list[Finding]]:
    """Return (passed, blocking_findings).

    A finding blocks when its severity is at or above the threshold and
    its key is not in the baseline.
    """
    baseline_keys = baseline_keys or set()
    cutoff = severity_rank(threshold)
    blocking = [
        f
        for f in findings
        if severity_rank(f.severity) >= cutoff and f.key not in baseline_keys
    ]
    return (len(blocking) == 0, blocking)


def load_baseline(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {str(k) for k in data.get("baseline_keys", [])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AppSec severity gate")
    parser.add_argument("--sarif", action="append", default=[], help="SARIF file")
    parser.add_argument("--pip-audit", help="pip-audit JSON output file")
    parser.add_argument("--baseline", help="JSON file with baseline_keys list")
    parser.add_argument("--threshold", default="high", choices=SEVERITY_ORDER)
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    try:
        for path in args.sarif:
            with open(path, encoding="utf-8") as fh:
                findings.extend(findings_from_sarif(json.load(fh)))
        if args.pip_audit:
            with open(args.pip_audit, encoding="utf-8") as fh:
                findings.extend(findings_from_pip_audit(json.load(fh)))
        baseline = load_baseline(args.baseline) if args.baseline else set()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"gate: cannot read scanner output ({exc}); failing closed")
        return 2

    passed, blocking = evaluate(findings, args.threshold, baseline)
    for f in blocking:
        print(f"BLOCKING [{f.severity}] {f.tool} {f.rule_id} at {f.location}")
    print(
        f"gate: {len(findings)} findings, {len(blocking)} blocking "
        f"(threshold={args.threshold}) -> {'PASS' if passed else 'FAIL'}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
