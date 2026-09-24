# Module 03 — SAST : analyse statique du code

> ⏱️ 3 h · 🎯 Trouver les failles dans le code source, trier les résultats, écrire ses propres règles

## Objectifs

- Comprendre comment fonctionne un outil SAST (motifs, *taint analysis*)
- Lancer **Semgrep** et **Bandit**, comparer leurs résultats
- Identifier les faux positifs et les faux négatifs
- Écrire une règle Semgrep personnalisée
- Corriger le code de VulnShop

## 1. Cours

### 1.1 Comment un SAST « lit » le code

Un outil SAST ne lance pas l'application. Il analyse le code source :

- **Recherche de motifs** : « un appel à `yaml.load` sans `SafeLoader` » → alerte.
  Simple, rapide, mais ne sait pas si la donnée est dangereuse.
- **Analyse de flux (*taint*)** : suit une donnée depuis une **source** non fiable
  (`request.args`) jusqu'à un **puits** dangereux (`cursor.execute`, `subprocess`),
  en passant éventuellement par des **nettoyeurs** (*sanitizers*) qui la rendent sûre.

```
 source                     propagation                    puits
request.args.get("q")  ──►  query = "..." % q   ──►  db.execute(query)   ⚠️
```

### 1.2 Forces et limites

| ✅ Forces | ❌ Limites |
|---|---|
| Tourne en quelques secondes, dès le commit | Ne voit pas la configuration d'exécution |
| Pointe la ligne exacte à corriger | Faux positifs (manque de contexte) |
| Couvre 100 % du code, même les branches jamais testées | Faux négatifs (règle absente, flux trop complexe) |
| S'intègre dans l'IDE et la CI | Ne comprend pas la logique métier (contrôle d'accès) |

### 1.3 Les outils du lab

- **Semgrep** : multi-langages, règles lisibles en YAML qui ressemblent au code ciblé.
  Registre de règles publiques (`p/python`, `p/flask`, `p/owasp-top-ten`…).
- **Bandit** : spécifique à Python, maintenu par PyCQA, très simple.
- À connaître aussi : CodeQL (GitHub, gratuit sur dépôt public), SonarQube, Snyk Code.

## 2. Lab

### 2.1 Premier scan et triage

```bash
make sast
```

Pour chaque résultat, note dans ton journal : **règle, ligne, vrai ou faux positif ?**
Compare avec les commentaires `VULN-xx` de [app/app.py](../../app/app.py).

❓ Quelles failles `VULN-xx` Semgrep **n'a pas** trouvées ?

### 2.2 Un second avis : Bandit

```bash
make bandit
```

Construis un tableau à trois colonnes : *VULN-xx* / *Semgrep* / *Bandit*.
❓ Quel outil a trouvé quoi ? Qu'en conclus-tu sur l'usage d'un seul outil ?

### 2.3 Écrire ta propre règle

Le dossier [rules/semgrep/](../../rules/semgrep/) contient une règle d'exemple, lancée par
`make sast-custom`.

1. Lis [example.yml](../../rules/semgrep/example.yml) et lance `make sast-custom`.
   ❓ Pourquoi 0 résultat ? Ajoute un `print()` dans l'app pour vérifier que la règle marche.
2. Écris `rules/semgrep/deserialization.yml` : une règle **en mode taint** qui alerte quand
   une donnée issue de `flask.request` arrive dans `pickle.loads`.
   Aide : <https://semgrep.dev/docs/writing-rules/data-flow/taint-mode>
3. Vérifie qu'elle trouve la ligne `VULN-07` — et qu'elle ne se déclenche **pas** si tu
   remplaces temporairement la donnée par une constante.

### 2.4 Gérer un faux positif proprement

Imagine qu'une alerte soit un faux positif légitime. Il existe deux façons de la faire taire :

```python
x = something()  # nosemgrep: <id-de-la-règle>
```

ou exclure un chemin dans un fichier `.semgrepignore`.
❓ Quelle est la différence en termes de traçabilité ? Pourquoi une suppression doit-elle
**toujours** s'accompagner d'un commentaire justifiant la décision ?

### 2.5 Corriger VulnShop

Corrige chaque faille remontée, puis relance `make sast STRICT=1 && make bandit STRICT=1`
jusqu'à obtenir un code de retour `0`. Règles de correction :

| Faille | Correction attendue |
|---|---|
| SQL concaténé | requête paramétrée (`?`) |
| Template construit avec l'entrée | template fixe + variable passée en paramètre (échappement auto) |
| `shell=True` | liste d'arguments, pas de shell, validation stricte de l'entrée |
| `yaml.load` | `yaml.safe_load` |
| `pickle.loads` | `json.loads` (données) — jamais de pickle sur une entrée externe |
| MD5 | `werkzeug.security.generate_password_hash` (ou argon2/bcrypt) |
| `debug=True`, `0.0.0.0` | pilotés par variables d'environnement, désactivés par défaut |

> 💡 Travaille sur une branche (`git switch -c fix/sast`) : la version vulnérable de `main`
> reste disponible pour les autres modules.

## 3. Corrigés

<details>
<summary>2.1 / 2.2 — Qui trouve quoi ?</summary>

| Faille | Semgrep (p/python, p/flask, p/secrets) | Bandit |
|---|---|---|
| VULN-01 secret codé en dur | ❌ | ✅ B105 |
| VULN-02 MD5 | ✅ | ✅ B324 |
| VULN-03 SQL | ✅ (taint) | ✅ B608 |
| VULN-04 template | ✅ | ❌ |
| VULN-05 commande | ✅ (taint) | ✅ B602 |
| VULN-06 YAML | ✅ | ✅ B506 |
| VULN-07 pickle | ❌ | ✅ B301 |
| VULN-08 debug / 0.0.0.0 | ✅ | ✅ B201 / B104 |

Aucun outil ne couvre tout : combiner deux analyseurs, c'est déjà réduire les faux négatifs.
Note aussi que Bandit signale de simples `import pickle` / `import subprocess` (B403/B404)
en sévérité LOW : ce sont des « points d'attention », souvent des faux positifs.
</details>

<details>
<summary>2.3 — Règle taint pour la désérialisation</summary>

```yaml
rules:
  - id: flask-untrusted-deserialization
    message: >-
      Des données venant de la requête HTTP sont désérialisées avec pickle/marshal.
      Un attaquant peut exécuter du code arbitraire. Utilise json à la place.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"
      owasp: "A08:2021 - Software and Data Integrity Failures"
    mode: taint
    pattern-sources:
      - pattern: flask.request.$ANYTHING
    pattern-sinks:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: marshal.loads(...)
```

Semgrep suit la donnée à travers `request.args.get(...)` puis `base64.b64decode(...)`
jusqu'à `pickle.loads` : 1 résultat, ligne 114.
</details>

<details>
<summary>2.4 — Suppression de faux positifs</summary>

`# nosemgrep: règle` est **local et visible en revue de code** : on voit qui a ignoré quoi,
à quel endroit, et on peut exiger une justification dans la PR. `.semgrepignore` exclut des
fichiers entiers, silencieusement : pratique pour du code généré ou des tests, dangereux
sinon. Dans les deux cas, un commentaire du type
`# nosemgrep: règle -- entrée validée par regex ligne 42, cf. revue #123` évite qu'on se
demande dans 6 mois pourquoi l'alerte a disparu.
</details>

<details>
<summary>2.5 — Extraits de corrections</summary>

```python
from werkzeug.security import generate_password_hash
import ipaddress, json, logging

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
        ipaddress.ip_address(host)          # n'accepte qu'une adresse IP
    except ValueError:
        return jsonify({"error": "adresse IP invalide"}), 400
    out = subprocess.run(["ping", "-c", "1", host],
                         capture_output=True, text=True, timeout=5)
    return jsonify({"output": out.stdout})

@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.safe_load(request.data)
    return jsonify({"imported": str(config)})

@app.route("/session")
def restore_session():
    obj = json.loads(base64.b64decode(request.args.get("data", "")))
    return jsonify({"session": obj})

# init_db : generate_password_hash(pwd) au lieu de hashlib.md5(...)

if __name__ == "__main__":
    init_db()
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG") == "1")
```

Dans le conteneur, on passera `HOST=0.0.0.0` (le conteneur est isolé) — et en production on
remplacera le serveur de développement Flask par **gunicorn** (module 05).
</details>

## ✅ Checklist

- [ ] J'ai trié les résultats Semgrep (vrai / faux positif)
- [ ] J'ai comparé Semgrep et Bandit
- [ ] Ma règle taint trouve VULN-07
- [ ] Sur ma branche de correction, `make sast STRICT=1` passe

➡️ [Module 04 — SCA & SBOM](../04-sca-sbom/README.md)
