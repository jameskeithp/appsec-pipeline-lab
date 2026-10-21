#!/usr/bin/env python3
"""
INTENTIONALLY VULNERABLE TRAINING APPLICATION -- DO NOT DEPLOY.

This Flask app exists for one purpose: to give the SAST, SCA, and DAST
scanners in this repository something real to find. Every vulnerability
below is deliberate, clearly commented, and catalogued in
docs/sample-findings.md. It binds to localhost in the demo scripts and
must never be exposed to a network you care about, given real data, or
copied into production code.

Vulnerability catalogue (each one maps to a scanner rule in the lab):
  1. SQL injection            -- /user builds SQL with string formatting
  2. Reflected XSS            -- /search echoes input without escaping
  3. Hardcoded secret         -- SECRET_KEY and an API token in source
  4. Weak cryptography        -- MD5 used for password storage in /register
  5. Insecure deserialization -- pickle.loads on request data in /restore
  6. Flask debug mode         -- app.run(debug=True) under __main__
"""

import hashlib
import pickle
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# VULNERABILITY 3 (hardcoded secret): real applications load secrets from
# the environment or a secret manager. A committed secret is compromised
# the moment it lands in git history, even if it is "removed" later.
app.config["SECRET_KEY"] = "hardcoded-dev-secret-do-not-use"
THIRD_PARTY_API_TOKEN = "sk-live-EXAMPLE-hardcoded-token-not-real"


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password_hash TEXT)"
    )
    conn.execute(
        "INSERT INTO users (name, password_hash) VALUES ('alice', 'placeholder')"
    )
    return conn


@app.route("/")
def index():
    return (
        "<h1>appsec-pipeline-lab target app</h1>"
        "<p>Intentionally vulnerable training target. See README.md.</p>"
    )


@app.route("/user")
def user_lookup():
    """VULNERABILITY 1 (SQL injection).

    The `name` parameter is interpolated straight into the SQL string.
    A request like /user?name=' OR '1'='1 returns every row. The fix is
    a parameterized query: cursor.execute("... WHERE name = ?", (name,)).
    Semgrep rule python.flask / python.lang.security.audit should flag
    the string-formatted execute() call below.
    """
    name = request.args.get("name", "")
    conn = get_db()
    query = "SELECT id, name FROM users WHERE name = '%s'" % name
    rows = conn.execute(query).fetchall()
    return {"users": [{"id": r[0], "name": r[1]} for r in rows]}


@app.route("/search")
def search():
    """VULNERABILITY 2 (reflected XSS).

    The `q` parameter is reflected into HTML with no escaping and no
    Content-Security-Policy. /search?q=<script>alert(1)</script> executes
    in a victim's browser. The fix is output encoding (Jinja2 autoescape
    or markupsafe.escape). ZAP's baseline scan flags the missing CSP and
    the reflection.
    """
    q = request.args.get("q", "")
    return f"<html><body><h2>Results for: {q}</h2></body></html>"


@app.route("/register", methods=["POST"])
def register():
    """VULNERABILITY 4 (weak cryptography).

    Passwords are hashed with unsalted MD5, which modern GPUs crack at
    billions of guesses per second. The fix is a password KDF: bcrypt,
    scrypt, or argon2 with per-user salt. Semgrep flags hashlib.md5 on
    security-sensitive data.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    digest = hashlib.md5(password.encode()).hexdigest()  # nosec: deliberate
    return {"registered": username, "stored_hash_preview": digest[:8]}


@app.route("/restore", methods=["POST"])
def restore():
    """VULNERABILITY 5 (insecure deserialization).

    pickle.loads on attacker-controlled bytes is remote code execution
    by design: a crafted pickle runs arbitrary code during unpickling.
    The fix is a data-only format (JSON) plus schema validation. Semgrep
    and CodeQL both flag pickle.loads on request data.
    """
    blob = request.get_data()
    obj = pickle.loads(blob)  # nosec: deliberate, training target only
    return {"restored_type": type(obj).__name__}


if __name__ == "__main__":
    # VULNERABILITY 6 (debug mode): the Werkzeug debugger allows code
    # execution from the browser if reached. Never run debug=True outside
    # a throwaway local lab. Kept here so scanners have a true positive.
    app.run(host="127.0.0.1", port=5000, debug=True)
