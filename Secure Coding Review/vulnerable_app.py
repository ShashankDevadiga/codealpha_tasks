"""
vulnerable_app.py  —  intentionally insecure Flask demo
WARNING: Do NOT deploy this. For educational/audit purposes only.
"""

import sqlite3
import subprocess
import pickle
import os
from flask import Flask, request, render_template_string, session, redirect
import hashlib
import yaml

app = Flask(__name__)
app.secret_key = "supersecret123"  # [V-008] Hardcoded secret key


# ── V-001: SQL Injection ─────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULN: Direct string interpolation in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        session["user"] = username
        return redirect("/dashboard")
    return "Login failed", 401


# ── V-002: Server-Side Template Injection ────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # VULN: User input directly rendered as template
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


# ── V-003: OS Command Injection ──────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host")
    # VULN: User input passed to shell command
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result


# ── V-004: Insecure Deserialization ──────────────────────────────────────────
@app.route("/load_profile", methods=["POST"])
def load_profile():
    data = request.get_data()
    # VULN: Unpickling untrusted data → arbitrary code execution
    profile = pickle.loads(data)
    return str(profile)


# ── V-005: Weak Password Hashing ─────────────────────────────────────────────
def hash_password(password):
    # VULN: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# ── V-006: Path Traversal ────────────────────────────────────────────────────
@app.route("/read_file")
def read_file():
    filename = request.args.get("filename")
    # VULN: No path sanitization → ../../etc/passwd
    with open(f"/var/data/{filename}", "r") as f:
        return f.read()


# ── V-007: YAML Arbitrary Code Execution ─────────────────────────────────────
@app.route("/config", methods=["POST"])
def load_config():
    config_data = request.get_data(as_text=True)
    # VULN: yaml.load without Loader allows object instantiation
    config = yaml.load(config_data)
    return str(config)


# ── V-008: Debug Mode + Insecure Cookie ──────────────────────────────────────
@app.route("/set_admin")
def set_admin():
    resp = redirect("/dashboard")
    # VULN: Cookie with no secure/httponly flags
    resp.set_cookie("role", "admin", secure=False, httponly=False)
    return resp


if __name__ == "__main__":
    # VULN: debug=True exposes Werkzeug interactive debugger (RCE)
    app.run(debug=True, host="0.0.0.0")
