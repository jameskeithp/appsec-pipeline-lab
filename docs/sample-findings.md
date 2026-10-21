# Sample findings report

What the scanners actually found when this lab was built and run
locally on **2026-10-21**, in this project's build environment
(Python 3.12.3, Linux VM). Nothing in this report is illustrative or
reconstructed: every number below came out of a tool run whose raw
output is reproducible with the scripts in `scripts/`. Where a tool
could not run in this environment, this report says so and explains
what runs in CI instead.

## Run summary

| Stage | Tool | Ran locally? | Result |
|---|---|---|---|
| SAST | Semgrep 1.182.0 | Yes | 190 rules, **8 findings** in `app/app.py` |
| SCA | pip-audit 2.10.1 | Yes | **45 unique advisories** across all 6 pinned dependencies |
| Gate | `tools/gate.py` | Yes | 53 findings total, **46 blocking, FAIL (exit 1)** -- as designed |
| Unit tests | pytest 9.1.1 | Yes | **9 passed** (`tests/test_gate.py`) |
| SAST 2 | CodeQL | No -- CI only | Requires the CodeQL CLI / GitHub Actions; the workflow's `sast-codeql` job runs it with `security-extended` queries and uploads SARIF. Not run locally, so no local findings are claimed for it. |
| DAST | OWASP ZAP baseline | No -- no Docker in this VM | `scripts/run_dast.sh` and the CI `dast` job both need the ZAP container / `zaproxy/action-baseline`. Docker is not installed in this build environment (verified), so no ZAP results are reported here rather than invented. Expected CI findings on this target include missing Content-Security-Policy and anti-clickjacking headers, which `.zap/rules.tsv` sets to `FAIL`, plus the reflected input on `/search` for passive rules to observe. |

Reproduce the local stages:

```bash
pip install semgrep pip-audit pytest
./scripts/run_sast.sh     # -> results/semgrep.sarif
./scripts/run_sca.sh      # -> results/pip-audit.json
python3 tools/gate.py --sarif results/semgrep.sarif \
                      --pip-audit results/pip-audit.json \
                      --baseline policy/baseline.json --threshold high
python3 -m pytest tests/ -q
```

## SAST findings (Semgrep, configs: p/python, p/secrets, p/owasp-top-ten)

All 8 findings are true positives against the deliberate
vulnerabilities in `app/app.py`:

| # | Rule | Location | Deliberate flaw |
|---|---|---|---|
| 1 | `python.flask.security.injection.tainted-sql-string` | `app/app.py:67` | SQL built by string formatting from request input (SQL injection) |
| 2 | `python.django.security.injection.sql.sql-injection-using-db-cursor-execute` | `app/app.py:65` | Tainted data reaching `cursor.execute()` (same SQLi, second rule) |
| 3 | `python.flask.security.audit.directly-returned-format-string` | `app/app.py:83` | Formatted string returned directly from a Flask route (reflected XSS) |
| 4 | `python.django.security.injection.raw-html-format` | `app/app.py:83` | User input in manually built HTML (same XSS) |
| 5 | `python.flask.security.injection.raw-html-concat.raw-html-format` | `app/app.py:83` | Same XSS, third rule |
| 6 | `python.lang.security.insecure-hash-algorithms-md5` | `app/app.py:97` | MD5 used as a hash algorithm |
| 7 | `python.lang.security.audit.md5-used-as-password` | `app/app.py:97` | MD5 used for password storage |
| 8 | `python.flask.security.audit.debug-enabled` | `app/app.py:119` | Flask `debug=True` |

Severity note: Semgrep's SARIF export from this version carries the
rules' ERROR/WARNING levels in `defaultConfiguration.level`;
`tools/gate.py` reads that (covered by a unit test). One finding (the
tainted SQL string) is ERROR and blocks at the `high` threshold; the
rest are WARNING (normalized to medium) and report without blocking.

### Honest misses

Two planted flaws were **not** flagged by the local Semgrep packs, and
this report names them instead of rounding the result up to perfect:

- `pickle.loads` on request data (`app/app.py`, `/restore`): not
  matched by p/python + p/owasp-top-ten as run here. CodeQL's
  security-extended set (CI) includes unsafe-deserialization queries;
  whether it fires is a CI result, not claimed here.
- The hardcoded secret strings: the values are deliberately fake
  (`sk-live-EXAMPLE-...`), and entropy/pattern-based secret rules are
  tuned to avoid exactly such examples. A real leaked key is what
  p/secrets and push-protection exist to catch.

Lesson the lab is built to teach: scanner coverage is per-rule and
per-pack. "The SAST passed" never means "there are no bugs"; it means
these rules found nothing, which is why the pipeline layers SAST, SCA,
DAST, and human review.

## SCA findings (pip-audit, against `app/requirements.txt`)

pip-audit reported advisories against **every** pinned dependency.
Its raw JSON repeats an advisory once per affected version range;
`tools/gate.py` deduplicates to one finding per (package, advisory).
Unique counts from the actual run:

| Package | Pinned | Unique advisories | Example |
|---|---|---|---|
| Flask | 2.2.3 | 2 | PYSEC-2023-62 (CVE-2023-30861, response caching / session cookie leak) |
| Werkzeug | 2.2.3 | 9 | PYSEC-2023-221 and eight later advisories |
| Jinja2 | 3.1.2 | 5 | PYSEC-2026-1471 .. PYSEC-2026-1475 |
| requests | 2.28.1 | 4 | PYSEC-2023-74 and three later advisories |
| urllib3 | 1.26.14 | 10 | PYSEC-2023-192, PYSEC-2023-212 (redirect handling) and eight later |
| cryptography | 39.0.0 | 15 | PYSEC-2023-11 plus GHSA advisories for the bundled OpenSSL |

Per the triage policy (`docs/triage-and-slas.md`), pip-audit findings
are gated as **high** while a fix version exists, which is why 45 of
the 46 blocking findings come from this stage. In a real codebase that
volume at adoption time is exactly what the baseline process exists
for: triage once, record accepted risk with expiry, ratchet from
there. On this lab the pins stay vulnerable on purpose.

## Gate result

```
$ python3 tools/gate.py --sarif results/semgrep.sarif \
                        --pip-audit results/pip-audit.json \
                        --baseline policy/baseline.json --threshold high
gate: 53 findings, 46 blocking (threshold=high) -> FAIL   (exit code 1)
```

The gate failing on this repository is the success criterion: it
proves the policy fires on real findings. The gate also fails closed
(exit 2) on missing or unparseable scanner output; both behaviors are
covered by unit tests.
