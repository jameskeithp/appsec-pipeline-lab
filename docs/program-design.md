# Program design: from this lab to a real AppSec program

This lab is one repository's pipeline. A program is what happens when
the same ideas run across every repository a company owns. This note
describes how the pieces here scale, because "I can configure Semgrep"
and "I can run an AppSec program" are different claims and interviewers
know it.

## The pipeline as the program's sensor

- **PR-time feedback (shift left, but keep it fast).** Semgrep and
  dependency review run on every pull request and answer in minutes.
  CodeQL's deeper analysis runs on merge and on a schedule, where its
  latency does not stall developers. ZAP baseline runs against staging
  on deploy. Full authenticated DAST and manual testing sit above the
  baseline for high-risk services; automation does not replace them.
- **One policy, centrally owned.** Severity mapping, the gate
  threshold, and SLAs live in one place (`tools/gate.py`,
  `docs/triage-and-slas.md`) and are consumed by every repo, so "what
  counts as blocking" is a program decision, not per-team folklore.
  The reusable-workflow version of `appsec.yml` is how this ships to
  dozens of repos without dozens of forks of the YAML.
- **SARIF is the integration contract.** Every scanner emits SARIF (or
  is adapted to it), lands in the GitHub Security tab, and from there
  can flow to whatever system of record the company uses (Jira,
  ServiceNow, an ASPM platform) without re-integrating each tool.

## Developer experience is a security control

- Findings arrive where developers already work: PR checks, the
  Security tab, a ticket with the exact location and a fix pattern.
  A finding that requires a wiki expedition to understand will be
  ignored, and that is the program's bug, not the developer's.
- The feedback loop is measured: time from finding to developer
  acknowledgment, false-positive rate per rule, and repeat-finding
  rate per team. Rules with high FP rates get tuned, scoped, or
  retired; scanner noise is treated as a defect in the program.
- Champions networks and office hours handle the "how do I fix this
  class" questions at scale; the pipeline handles the detection.

## Metrics that matter (and two that do not)

Report: mean time to remediate by severity against SLA, percentage of
repos with gating enabled, findings aging past SLA, FP rate per rule,
and vulnerability density trend per service. Do **not** report raw
finding counts as a KPI (they reward turning scanners off) or rank
teams by findings (they punish the teams whose code is scanned most).

## Risk-based rollout

1. Visibility first: scanners in report-only mode, findings flowing,
   nobody blocked. Baseline the existing state honestly.
2. Gate the worst: turn on blocking for critical, then high, per repo,
   with the baseline ratchet documented in
   `docs/false-positive-suppression.md`.
3. Expand coverage by risk tier: internet-facing and regulated-data
   services first, internal tooling later, with DAST depth and manual
   review allocated by data sensitivity, not by who shouts loudest.
4. Feed incidents back: every production security bug becomes a
   candidate scanner rule or test case, so the pipeline learns from
   the failures it missed.
