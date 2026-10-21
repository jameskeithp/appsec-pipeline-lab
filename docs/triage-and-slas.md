# Triage and severity SLAs

How a finding in this pipeline becomes fixed work, and how fast. The
policy the CI gate enforces (`tools/gate.py`) is the floor of this
document, not the whole of it: the gate blocks merges, humans own the
rest.

## Severity definitions

Severity is assigned by the scanner and normalized by `tools/gate.py`
onto one ladder: `note < low < medium < high < critical`. Where a tool
does not publish severity (pip-audit's JSON carries no per-CVE score),
the finding defaults conservatively:

| Source | Mapping |
|---|---|
| Semgrep | Rule severity, else SARIF level: error -> high, warning -> medium, note -> low |
| CodeQL | SARIF level and rule precision from the Security tab |
| pip-audit | Always **high** while a fix version exists: a dependency with a published CVE and a published fix is the cheapest class of finding to remediate, and the SCA stage exists to keep it out |
| ZAP baseline | High alerts fail the DAST job (`fail_action`); WARN rules in `.zap/rules.tsv` are triaged as medium by default |

A human triager can raise or lower severity with a written rationale in
the ticket (exploitability in this app's context, compensating
controls, data sensitivity). Scanner severity is the starting point,
not the verdict.

## Remediation SLAs

Clock starts at triage confirmation, not at scan time.

| Severity | Triage within | Fix or approved exception within | Gate behavior |
|---|---|---|---|
| Critical | 4 business hours | 24 hours | Blocks merge |
| High | 1 business day | 7 calendar days | Blocks merge |
| Medium | 3 business days | 30 calendar days | Warns; ticket required |
| Low / note | 5 business days | 90 calendar days or backlog | Reported only |

SLA breaches escalate to the engineering manager and the AppSec lead
jointly. An SLA is a commitment to respond, not a promise that every
fix is trivial; where a fix genuinely cannot land in window, the
exception process below is the honest path, not silent expiry.

## The gating policy (what CI actually enforces)

- Threshold: **high**. Any *new* finding at high or critical blocks
  the merge. "New" means its key
  (`tool|rule_id|location`, see `tools/gate.py`) is not in
  `policy/baseline.json`.
- The baseline is the adoption mechanism: a team turning this pipeline
  on for a legacy codebase triages existing findings once, records the
  accepted ones in the baseline with ticket references and expiry
  dates, and from that day forward the ratchet only tightens.
- The gate **fails closed** (exit code 2) if scanner output is missing
  or unparseable. A broken scanner must never look like a clean scan.
- On this lab repository the gate fails by design: the sample app's
  findings are real, unpatched, and unbaselined. Running the gate
  locally shows the exact findings a real team would triage first.

## Finding lifecycle

```
scan -> SARIF/JSON artifact -> gate (new high/critical blocks)
     -> GitHub Security tab (Semgrep + CodeQL SARIF)
     -> triage (confirm, severity, owner, due date per SLA)
     -> fix PR (re-scan must show the finding gone)
     -> close, or exception (baseline entry + ticket + expiry)
```

Every confirmed finding gets a ticket with: scanner, rule ID, location,
the data-flow or request that proves it, the fix or the exception, and
the SLA due date. Findings are never closed from the scanner UI alone.
