# False positives and suppression

Suppressing a finding is a security decision, so it is made in the
open, in version control, with an expiry date. Three mechanisms exist
in this repo, in descending order of preference:

## 1. Fix it (always the first option)

A suppression request starts with the question "why is fixing this
wrong?" If there is no good answer, there is no suppression.

## 2. Path and rule configuration (scanner-level)

- **Semgrep**: `.semgrepignore` excludes paths (tests, generated
  output). Inline `# nosemgrep: <rule-id>` comments suppress one line
  and must carry a justification comment and ticket reference on the
  line above. Example of the *form* (from a hypothetical production
  codebase, not this lab's target app):

  ```python
  # FP: input is an enum validated against ALLOWED_SORTS above.
  # Ticket: SEC-1234, expires 2027-01-01.
  query = build_query(sort)  # nosemgrep: python.lang.security.audit.sqli
  ```

- **ZAP**: `.zap/rules.tsv` sets per-rule thresholds
  (`IGNORE` / `WARN` / `FAIL`). This repo's file keeps missing-CSP and
  clickjacking protection at `FAIL` (they are real findings on the
  target app) and documents one `IGNORE` as a worked example of the
  format, with its reasoning written in the file itself.

## 3. The gate baseline (policy-level)

`policy/baseline.json` lists finding keys the gate will not block on.
An entry is an *accepted risk record*, not a delete button. Rules:

- One baseline entry per finding key, added in the same PR as the
  triage ticket reference.
- Every entry names an owner and an expiry (default 90 days, maximum
  180 for low severity). Expired entries are removed in a monthly
  review; the finding then blocks again until re-triaged.
- Critical findings cannot be baselined by the finding's own team;
  they need AppSec lead sign-off.
- The monthly review asks one question per entry: "is this still
  true, and is the fix still harder than the risk?" If the answer
  changed, the entry goes.

## What a good suppression record looks like

| Field | Example |
|---|---|
| Finding | semgrep `python.flask.security.xss` at `app/app.py:57` |
| Verdict | True positive, accepted risk (training target) |
| Rationale | The app is an intentional scanner target, localhost-only |
| Owner | AppSec lab maintainer |
| Ticket | LAB-001 |
| Expiry | Reviewed each release; not carried into any production fork |

On this lab repo the baseline is intentionally empty and the target
app's findings are *not* suppressed anywhere in scanner config: seeing
raw, unsuppressed output is what makes the demo honest.
