# Module 08 — DAST : tester l'application en fonctionnement

> ⏱️ 2 h 30 · 🎯 Observer l'application de l'extérieur, comme le ferait un attaquant, et vérifier les corrections

## Objectifs

- Comprendre la différence entre scan **passif** et scan **actif**
- Lancer **OWASP ZAP** en mode *baseline* puis *full scan*
- Comparer les résultats DAST avec ceux du SAST
- Durcir les en-têtes HTTP et vérifier la correction

> ⚖️ **Cadre légal.** Un scan DAST actif envoie de vraies requêtes d'attaque. Ne le lance
> **que** sur une cible qui t'appartient ou pour laquelle tu as une autorisation écrite.
> Dans ce lab : uniquement VulnShop, sur ton réseau Docker local.

## 1. Cours

### 1.1 Boîte blanche, boîte noire

| | SAST | DAST |
|---|---|---|
| Voit | le code source | les requêtes / réponses HTTP |
| Quand | dès le commit | sur une application déployée (recette, staging) |
| Trouve bien | motifs dangereux, flux de données | configuration serveur, en-têtes, comportement réel |
| Rate | configuration d'exécution, dépendances à l'exécution | code jamais atteint par le robot d'exploration |
| Localisation | ligne de code exacte | URL et paramètre |

Les deux se complètent. Une faille trouvée par **les deux** est quasi certaine et atteignable.

### 1.2 Passif ou actif

- **Baseline (passif)** : ZAP explore l'application (*spider*) et **observe** les réponses :
  en-têtes manquants, cookies mal configurés, fuites d'information. Rapide, sans risque :
  peut tourner à chaque *pull request*.
- **Full scan (actif)** : ZAP **attaque** chaque paramètre trouvé avec des charges
  d'injection. Plus long, peut modifier ou casser des données : à lancer sur un
  environnement dédié, typiquement la nuit ou avant une mise en production.

### 1.3 Les en-têtes de sécurité HTTP

| En-tête | Protège contre |
|---|---|
| `Content-Security-Policy` | XSS, injection de contenu (le plus important) |
| `X-Frame-Options` / `frame-ancestors` | *clickjacking* |
| `X-Content-Type-Options: nosniff` | interprétation d'un fichier dans le mauvais type |
| `Strict-Transport-Security` | rétrogradation HTTPS → HTTP (à mettre sur le proxy TLS) |
| `Referrer-Policy` | fuite d'URL vers des sites tiers |
| `Permissions-Policy` | accès aux API sensibles du navigateur (caméra, géolocalisation…) |
| `Cross-Origin-*-Policy` | isolation entre origines |

Référence : OWASP Secure Headers Project.

## 2. Lab

### 2.1 Scan passif

```bash
make run
make dast
```

Ouvre `reports/zap-report.html` dans ton navigateur.
1. Combien d'alertes, par niveau de risque ?
2. ZAP a-t-il trouvé l'injection SQL, le XSS, l'injection de commande ? Pourquoi ?
3. L'alerte « Vulnerable JS Library » : d'où vient ce JavaScript, alors que VulnShop n'en
   contient pas ? (indice : module 00, page d'erreur)

### 2.2 Scan actif

```bash
make dast-full          # ~8 minutes (durée bornée par ZAP_MAX_MINUTES)
```

Ouvre `reports/zap-full-report.html`.
1. Quelles nouvelles alertes HIGH apparaissent ?
2. Remplis le tableau comparatif dans ton journal : pour chaque `VULN-xx`, trouvé par
   SAST (Semgrep / Bandit) ? par DAST passif ? par DAST actif ?
3. Une faille d'injection n'est trouvée **que** par le SAST. Laquelle ? Pourquoi le robot
   ne l'a-t-il pas trouvée ?

### 2.3 Durcir les réponses HTTP

Sur ta branche de correction, ajoute à VulnShop un `@app.after_request` qui pose les
en-têtes du tableau 1.3 (sauf HSTS, qui n'a de sens qu'en HTTPS). Désactive le mode debug
et renvoie des erreurs génériques (`{"error": "erreur interne"}`) plutôt que la trace Python.

Objectif : `make dast STRICT=1` passe.

### 2.4 Réglages

ZAP accepte un fichier de règles pour ignorer ou durcir des alertes : génère-le avec
`-g gen.conf`, puis passe-le avec `-c`. Chaque ligne a la forme
`<id>\t<IGNORE|INFO|WARN|FAIL>\t<nom>`.
❓ Quelles alertes passerais-tu en `FAIL` (bloquantes) pour ton projet ? Lesquelles en
`IGNORE`, et comment justifierais-tu ce choix ?

## 3. Corrigés

<details>
<summary>2.1 — Scan passif</summary>

13 alertes : 5 MEDIUM (CSP absente, anti-clickjacking, fuite de SQL dans les réponses,
bibliothèque JS vulnérable, absence de jeton CSRF), 7 LOW, 1 informationnelle. Aucune
injection : le scan passif **n'envoie pas** de charge d'attaque. La bibliothèque JS
(jQuery) est celle du **débogueur Werkzeug**, servi parce que `debug=True` : une seule
option de configuration expose à la fois une console de débogage et du JavaScript vulnérable.
</details>

<details>
<summary>2.2 — Qui trouve quoi ?</summary>

| Faille | SAST | DAST passif | DAST actif |
|---|---|---|---|
| VULN-03 SQL (`/search`) | ✅ | ⚠️ « Source Code Disclosure - SQL » | ✅ SQL Injection |
| VULN-04 template (`/hello`) | ✅ | ❌ | ✅ XSS reflected + DOM |
| VULN-05 commande (`/ping`) | ✅ | ❌ | ❌ (dans le temps imparti) |
| VULN-06 / 07 désérialisation | ✅ (Bandit) | ❌ | ❌ |
| VULN-08 debug | ✅ | ✅ « Application Error Disclosure » | ✅ |
| En-têtes absents | ❌ | ✅ | ✅ |

`/import` n'accepte que `POST` avec un corps YAML, et `/session` attend du base64 : le robot
ne sait pas fabriquer ces entrées. Le DAST ne teste que ce qu'il sait atteindre et
comprendre ; on l'aide avec une définition OpenAPI de l'API (`zap-api-scan.py`).
</details>

<details>
<summary>2.3 — En-têtes de sécurité</summary>

```python
from werkzeug.exceptions import HTTPException

@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.errorhandler(Exception)
def handle_error(exc):
    if isinstance(exc, HTTPException):   # 404, 405… restent des 404, 405…
        return exc
    app.logger.exception("Erreur non gérée")   # la trace va dans les logs, pas au client
    return jsonify({"error": "erreur interne"}), 500
```

Résultat mesuré sur la branche `solution` : de 13 alertes à 1 avertissement mineur
(`Non-Storable Content`, conséquence voulue de `Cache-Control: no-store`), 0 échec.
Sans les directives `form-action` et `base-uri`, ZAP ajoute un second avertissement
(`CSP: Failure to Define Directive with No Fallback`) : `default-src` ne les couvre pas.
</details>

## ✅ Checklist

- [ ] Je sais expliquer quand lancer un scan passif et quand lancer un scan actif
- [ ] J'ai comparé SAST et DAST sur les mêmes failles
- [ ] Sur ma branche, `make dast STRICT=1` passe

➡️ [Module 09 — Supply chain](../09-supply-chain/README.md)
