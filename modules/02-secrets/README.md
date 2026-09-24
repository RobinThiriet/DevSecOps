# Module 02 — Gestion des secrets

> ⏱️ 2 h · 🎯 Ne plus jamais commiter un secret, et savoir réagir quand ça arrive

## Objectifs

- Comprendre pourquoi « supprimer le fichier » ne supprime pas le secret
- Détecter des secrets dans tout l'historique git avec **Gitleaks**
- Bloquer les secrets avant le commit avec **pre-commit**
- Écrire une règle de détection personnalisée
- Connaître la bonne procédure de remédiation

## 1. Cours

### 1.1 Pourquoi c'est la faille n°1 en pratique

Un secret (clé d'API, token, mot de passe, clé privée) commité dans git :
- reste **dans l'historique pour toujours**, même après `git rm` ;
- est copié dans chaque clone, fork, cache de CI, sauvegarde ;
- sur un dépôt public, est récupéré par des robots **en quelques minutes**.

### 1.2 Où mettre les secrets, alors ?

| Contexte | Solution |
|---|---|
| Développement local | fichier `.env` **listé dans `.gitignore`** + un `.env.example` sans valeurs |
| CI/CD | secrets chiffrés de la plateforme (GitHub *Actions secrets*, GitLab *CI/CD variables*) |
| Production | gestionnaire de secrets : HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, SOPS… |
| Mieux encore | **identités sans secret** : OIDC entre GitHub Actions et le cloud, rôles IAM, workload identity |

Le code ne contient que le **nom** du secret : `os.environ["DB_PASSWORD"]`.

### 1.3 Procédure quand un secret a fuité

L'ordre compte :

1. **Révoquer / faire tourner le secret immédiatement.** C'est la seule étape qui protège
   vraiment. Considère-le comme compromis dès qu'il a été poussé.
2. Vérifier les journaux d'accès du service concerné (a-t-il été utilisé ?).
3. Retirer le secret du code et le remplacer par une lecture depuis l'environnement.
4. *Optionnel* : réécrire l'historique (`git filter-repo`) — utile, mais **ne remplace
   jamais l'étape 1** : les clones existants gardent le secret.
5. Ajouter une protection pour que ça ne se reproduise pas (pre-commit, CI).

### 1.4 Les outils

- **Gitleaks** : regex + entropie, scanne fichiers ou historique git. Rapide, simple.
- **TruffleHog** : peut *vérifier* si un secret est encore actif auprès du fournisseur.
- **GitHub Secret Scanning / Push Protection** : côté plateforme, activé sur les dépôts publics.

## 2. Lab

### 2.1 Chasse aux secrets dans l'historique

```bash
./scripts/lab-secrets.sh                # crée /tmp/secret-lab avec 5 commits
cd /tmp/secret-lab
git log --oneline
ls                                      # le dossier a l'air propre...
```

1. Sans outil : retrouve les secrets avec `git log -p`. Combien en trouves-tu ?
2. Avec Gitleaks :
   ```bash
   docker run --rm -v /tmp/secret-lab:/src ghcr.io/gitleaks/gitleaks:v8.28.0 git /src --verbose
   ```
3. ❓ Gitleaks en trouve-t-il autant que toi ? Lequel manque-t-il ?

### 2.2 Écrire sa propre règle

Un des secrets du lab passe sous le radar des règles par défaut. Crée
`/tmp/secret-lab/.gitleaks.toml` qui **étend** la configuration par défaut
(`[extend] useDefault = true`) avec une règle qui détecte ce type de secret, puis relance :

```bash
docker run --rm -v /tmp/secret-lab:/src ghcr.io/gitleaks/gitleaks:v8.28.0 \
  git /src --config /src/.gitleaks.toml --verbose
```

Documentation : <https://github.com/gitleaks/gitleaks#configuration>

### 2.3 Scanner le dépôt de formation

```bash
cd ~/DevSecOps          # (ou l'endroit où tu as cloné ce dépôt)
make secrets
```

❓ `app/app.py` contient `SECRET_KEY = "..."` et `DB_PASSWORD = "..."`. Sont-ils détectés ?
Pourquoi un outil basé sur l'entropie a-t-il du mal avec les mots de passe faibles ?

### 2.4 Bloquer avant le commit

```bash
pipx install pre-commit        # ou : pip install --user pre-commit
pre-commit install             # installe le hook dans .git/hooks/pre-commit
pre-commit run --all-files
```

Puis, sur une branche de test, crée un fichier contenant un faux token au format GitHub
(`ghp_` suivi de 36 caractères alphanumériques) et essaie de le commiter. Le commit doit
être refusé. Supprime ensuite la branche.

> 💬 Un hook local se contourne avec `git commit --no-verify`. C'est pour ça qu'on garde
> **aussi** le scan en CI : le hook est un confort pour le développeur, la CI est la garantie.

### 2.5 Remédiation de VulnShop

Modifie [app/app.py](../../app/app.py) pour que `SECRET_KEY` et `DB_PASSWORD` viennent de
variables d'environnement, avec une erreur explicite si elles sont absentes. Adapte
`make run` ou crée un `.env.example` documentant les variables attendues.

## 3. Corrigés

<details>
<summary>2.1 — Le secret manquant</summary>

Gitleaks trouve la clé AWS (2 règles), le token GitHub (2 règles), mais **pas** l'URL
`postgres://admin:xxxx@db.internal/...` du fichier `.env` : c'est un faux négatif.
</details>

<details>
<summary>2.2 — Règle personnalisée</summary>

```toml
[extend]
useDefault = true

[[rules]]
id = "connection-string-password"
description = "Mot de passe dans une URL de connexion (postgres, mysql, mongodb...)"
regex = '''(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/]+:([^@\s]+)@'''
secretGroup = 1
keywords = ["postgres", "mysql", "mongodb", "redis", "amqp"]
```

`keywords` sert de pré-filtre (performance) et `secretGroup` indique quel groupe de la regex
est le secret (pour le masquage avec `--redact` et le calcul d'entropie).
</details>

<details>
<summary>2.5 — Secrets via l'environnement</summary>

```python
def require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variable d'environnement manquante : {name}")
    return value

app.config["SECRET_KEY"] = require_env("SECRET_KEY")
DB_PASSWORD = require_env("DB_PASSWORD")
```

Et au lancement : `docker run -e SECRET_KEY="$(openssl rand -hex 32)" -e DB_PASSWORD=... vulnshop:dev`.
Pense aussi à retirer `ENV DB_PASSWORD=...` du Dockerfile (module 05) et du manifeste
Kubernetes (module 06, utiliser un `Secret`).
</details>

## ✅ Checklist

- [ ] Je sais pourquoi la rotation passe avant la réécriture d'historique
- [ ] J'ai trouvé les 5 secrets du lab, dont un avec ma propre règle
- [ ] Le hook pre-commit bloque un commit contenant un token
- [ ] VulnShop lit ses secrets depuis l'environnement

➡️ [Module 03 — SAST](../03-sast/README.md)
