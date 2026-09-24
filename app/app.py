"""VulnShop — version corrigée (solution du projet final)."""
import base64
import binascii
import ipaddress
import json
import logging
import os
import sqlite3
import subprocess  # nosec B404 -- utilisé sans shell, cf. /ping
import tempfile

import yaml
from flask import Flask, g, jsonify, render_template_string, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnshop")


def require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variable d'environnement manquante : {name}")
    return value


app = Flask(__name__)
app.config["SECRET_KEY"] = require_env("SECRET_KEY")

DATABASE = os.environ.get("DATABASE_PATH", os.path.join(tempfile.gettempdir(), "vulnshop.db"))


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
        )
        db.execute("DELETE FROM users")
        for name, role in [("alice", "user"), ("bob", "user"), ("admin", "admin")]:
            pwd = os.environ.get(f"SEED_PASSWORD_{name.upper()}", os.urandom(16).hex())
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (name, generate_password_hash(pwd), role),
            )
        db.commit()


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cache-Control"] = "no-store"
    log.info("%s %s %s %s", request.remote_addr, request.method, request.path, resp.status_code)
    return resp


INDEX = """
<h1>VulnShop</h1>
<ul>
  <li><a href="/search?q=alice">/search?q=</a> — recherche d'utilisateur</li>
  <li><a href="/hello?name=World">/hello?name=</a> — page de bienvenue</li>
  <li><a href="/ping?host=127.0.0.1">/ping?host=</a> — outil réseau</li>
  <li>POST /import — import de configuration YAML</li>
  <li>GET /session?data= — restauration de session</li>
</ul>
"""


@app.route("/")
def index():
    return INDEX


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = get_db().execute(
        "SELECT id, username, role FROM users WHERE username = ?", (q,)
    ).fetchall()
    return jsonify({"results": rows})


@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    return render_template_string("<h2>Bonjour {{ name }} !</h2>", name=name)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return jsonify({"error": "adresse IP invalide"}), 400
    out = subprocess.run(  # nosec B603 B607 -- liste d'arguments, IP validée ci-dessus
        ["ping", "-c", "1", host], capture_output=True, text=True, timeout=5, check=False
    )
    return jsonify({"output": out.stdout})


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.safe_load(request.data)
    return jsonify({"imported": str(config)})


@app.route("/session")
def restore_session():
    try:
        obj = json.loads(base64.b64decode(request.args.get("data", ""), validate=True))
    except (binascii.Error, ValueError):
        return jsonify({"error": "session invalide"}), 400
    return jsonify({"session": obj})


@app.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, HTTPException):
        return exc
    log.exception("Erreur non gérée")
    return jsonify({"error": "erreur interne"}), 500


init_db()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
