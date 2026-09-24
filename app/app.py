"""
VulnShop - application VOLONTAIREMENT VULNÉRABLE.

⚠️  NE JAMAIS DÉPLOYER CETTE APPLICATION SUR UN RÉSEAU PUBLIC.
Elle sert uniquement de cible d'entraînement pour les modules DevSecOps
(SAST, SCA, DAST, conteneurs...). Chaque faille est repérée par un
commentaire "VULN-xx" pour que tu puisses vérifier ce que les outils trouvent
(et ce qu'ils ratent).
"""
import hashlib
import os
import pickle
import base64
import sqlite3
import subprocess

import yaml
from flask import Flask, request, render_template_string, g, jsonify

app = Flask(__name__)

# VULN-01 : secret codé en dur dans le code source
app.config["SECRET_KEY"] = "s3cr3t-k3y-do-not-commit"
DB_PASSWORD = "admin123"

DATABASE = os.path.join(os.path.dirname(__file__), "vulnshop.db")


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
        # VULN-02 : mots de passe hachés en MD5 (algorithme cassé, sans sel)
        for name, pwd, role in [("alice", "alice2024", "user"),
                                ("bob", "b0b", "user"),
                                ("admin", "SuperAdmin!", "admin")]:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (name, hashlib.md5(pwd.encode()).hexdigest(), role),
            )
        db.commit()


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
    # VULN-03 : injection SQL (concaténation de chaîne)
    query = "SELECT id, username, role FROM users WHERE username = '%s'" % q
    rows = get_db().execute(query).fetchall()
    return jsonify({"query": query, "results": rows})


@app.route("/hello")
def hello():
    name = request.args.get("name", "World")
    # VULN-04 : XSS réfléchi + SSTI (entrée utilisateur injectée dans le template)
    return render_template_string("<h2>Bonjour " + name + " !</h2>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN-05 : injection de commande (shell=True + entrée non filtrée)
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return "<pre>" + out.decode() + "</pre>"


@app.route("/import", methods=["POST"])
def import_config():
    # VULN-06 : désérialisation YAML non sûre
    config = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify({"imported": str(config)})


@app.route("/session")
def restore_session():
    data = request.args.get("data", "")
    # VULN-07 : désérialisation pickle de données contrôlées par l'utilisateur
    obj = pickle.loads(base64.b64decode(data))
    return jsonify({"session": str(obj)})


if __name__ == "__main__":
    init_db()
    # VULN-08 : mode debug activé + écoute sur toutes les interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
