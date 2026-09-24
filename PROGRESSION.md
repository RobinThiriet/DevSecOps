# 📒 Journal de bord

Coche au fur et à mesure et note tes réponses : c'est ta mémoire du cursus, et une bonne
base pour un entretien (« raconte-moi comment tu as sécurisé un pipeline »).

## Avancement

- [ ] 00 — Démarrage
- [ ] 01 — Fondamentaux
- [ ] 02 — Secrets
- [ ] 03 — SAST
- [ ] 04 — SCA & SBOM
- [ ] 05 — Conteneurs
- [ ] 06 — Infrastructure as Code
- [ ] 07 — CI/CD
- [ ] 08 — DAST
- [ ] 09 — Supply chain
- [ ] 10 — Kubernetes & runtime
- [ ] 11 — Projet final

## Module 00 — Premier scan

- Nombre de problèmes Semgrep :
- Catégories OWASP reconnues :
- Pourquoi le code de retour compte en CI :

## Module 01 — Matrice STRIDE de VulnShop

| Endpoint / élément | S | T | R | I | D | E | OWASP | Outil qui devrait le trouver |
|---|---|---|---|---|---|---|---|---|
| `/search` | | | | | | | | |
| `/hello` | | | | | | | | |
| `/ping` | | | | | | | | |
| `/import` | | | | | | | | |
| `/session` | | | | | | | | |
| stockage des mots de passe | | | | | | | | |
| configuration (`SECRET_KEY`, debug) | | | | | | | | |
| dépendances | | | | | | | | |

## Qui trouve quoi ? (à compléter au fil des modules)

| Faille | Gitleaks | Semgrep | Bandit | Trivy | Hadolint | Checkov | ZAP passif | ZAP actif |
|---|---|---|---|---|---|---|---|---|
| VULN-01 secret codé en dur | | | | | | | | |
| VULN-02 MD5 | | | | | | | | |
| VULN-03 SQL | | | | | | | | |
| VULN-04 template | | | | | | | | |
| VULN-05 commande | | | | | | | | |
| VULN-06 YAML | | | | | | | | |
| VULN-07 pickle | | | | | | | | |
| VULN-08 debug | | | | | | | | |
| VULN-09 dépendances | | | | | | | | |
| VULN-10 Dockerfile | | | | | | | | |

## Mes exceptions (et leur justification)

| Outil | Règle | Fichier | Justification | À réévaluer le |
|---|---|---|---|---|
| | | | | |

## Notes libres

