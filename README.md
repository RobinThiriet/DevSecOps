# 🛡️ DevSecOps Lab

Un cursus **pratique** pour apprendre le DevSecOps : 12 modules de cours et d'exercices
autour d'une même application volontairement vulnérable, **VulnShop**, qu'on scanne,
corrige et déploie de façon sécurisée, du premier commit jusqu'au cluster Kubernetes.

> ⚠️ **Ce dépôt contient du code volontairement vulnérable** (`app/`, `infra/`).
> Ne le déploie jamais sur un serveur accessible depuis un réseau. Tout est conçu pour
> tourner en local, dans Docker, sur `127.0.0.1`.

## Démarrage rapide

```bash
git clone git@github.com:RobinThiriet/DevOps.git && cd DevOps
make help            # toutes les commandes
make run             # lance VulnShop sur http://127.0.0.1:5000
make scan-all        # lance tous les scanners statiques
```

Prérequis : **Git, Docker, make, curl**. Tous les outils de sécurité tournent dans des
conteneurs aux versions figées : rien d'autre à installer. Détails au
[module 00](modules/00-demarrage/README.md).

## Le cursus

| # | Module | Thème | Outils | Durée |
|---|---|---|---|---|
| 00 | [Démarrage](modules/00-demarrage/README.md) | environnement, organisation du dépôt | Docker, make | 45 min |
| 01 | [Fondamentaux](modules/01-fondamentaux/README.md) | shift-left, OWASP Top 10, STRIDE | — | 2 h |
| 02 | [Secrets](modules/02-secrets/README.md) | détection, pre-commit, remédiation | Gitleaks, pre-commit | 2 h |
| 03 | [SAST](modules/03-sast/README.md) | analyse statique, règles maison | Semgrep, Bandit | 3 h |
| 04 | [SCA & SBOM](modules/04-sca-sbom/README.md) | dépendances, CVE/EPSS/KEV, SBOM | Trivy, Syft, Grype | 2 h 30 |
| 05 | [Conteneurs](modules/05-conteneurs/README.md) | Dockerfile, image minimale, durcissement | Hadolint, Trivy | 3 h |
| 06 | [Infrastructure as Code](modules/06-iac/README.md) | Terraform, Kubernetes, policy as code | Checkov, Trivy | 3 h |
| 07 | [CI/CD](modules/07-ci-cd/README.md) | pipeline, security gates, Code scanning | GitHub Actions, zizmor | 3 h |
| 08 | [DAST](modules/08-dast/README.md) | scan dynamique, en-têtes HTTP | OWASP ZAP | 2 h 30 |
| 09 | [Supply chain](modules/09-supply-chain/README.md) | épinglage, Dependabot, signature, SLSA | cosign, Dependabot | 3 h |
| 10 | [Kubernetes & runtime](modules/10-kubernetes-runtime/README.md) | admission, politiques, CIS, détection | kind, PSA, Kyverno, kube-bench, Falco | 3 h |
| 11 | [Projet final](modules/11-projet-final/README.md) | tout sécuriser, pipeline strict au vert | tout | 1–2 j |

Chaque module suit la même structure : **objectifs → cours → lab guidé → corrigés**
(repliés, à n'ouvrir qu'après avoir cherché) → checklist.
Note ta progression et tes réponses dans [PROGRESSION.md](PROGRESSION.md).

## Organisation du dépôt

```
app/                    VulnShop : application Flask vulnérable (cible de tous les modules)
infra/terraform/        infrastructure AWS mal configurée (jamais appliquée)
infra/k8s/              manifeste Kubernetes mal configuré
modules/                cours et labs
rules/semgrep/          tes règles Semgrep maison         → make sast-custom
rules/checkov/          tes politiques Checkov maison     → make iac
scripts/                préparation des labs
.github/workflows/      pipeline DevSecOps (appelle les cibles make)
.pre-commit-config.yaml hooks exécutés avant chaque commit
Makefile                toutes les commandes
reports/                rapports générés (ignorés par git)
```

## Les commandes

| Commande | Module | Ce qu'elle fait |
|---|---|---|
| `make run` / `make stop` | 00 | lance / arrête VulnShop |
| `make secrets` | 02 | secrets dans tout l'historique git (Gitleaks) |
| `make sast` / `make bandit` / `make sast-custom` | 03 | analyse statique (Semgrep, Bandit, tes règles) |
| `make sca` | 04 | CVE des dépendances (Trivy) |
| `make sbom` / `make sbom-scan` | 04 | génère le SBOM (Syft) et le scanne (Grype) |
| `make lint-docker` / `make image-scan` | 05 | Dockerfile (Hadolint) et image (Trivy) |
| `make iac` | 06 | Terraform et Kubernetes (Checkov) |
| `make ci-audit` | 07 / 09 | sécurité des workflows GitHub Actions (zizmor) |
| `make dast` / `make dast-full` | 08 | scan ZAP passif / actif de l'app en cours d'exécution |
| `make scan-all` | — | tous les scans statiques |

Par défaut, les scans **affichent** les problèmes sans échouer (mode apprentissage).
Ajoute `STRICT=1` pour qu'ils deviennent des *security gates* bloquantes :

```bash
make sast STRICT=1; echo "code de retour : $?"
```

## Branches

- **`main`** : la version vulnérable, point de départ de tous les exercices.
- **`solution`** : une version entièrement corrigée, pipeline en mode strict tout vert.
  À consulter **après** avoir fait les exercices : `git diff main origin/solution`.

Travaille sur tes propres branches (`git switch -c fix/sast`…) pour garder `main` intacte.

## Avertissement

Ce projet est destiné à la formation. Les failles sont documentées et volontaires. Les
techniques de scan dynamique (module 08) ne doivent être utilisées que sur des systèmes
qui t'appartiennent ou pour lesquels tu disposes d'une autorisation écrite.
