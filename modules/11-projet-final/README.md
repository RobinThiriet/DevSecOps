# Module 11 — Projet final : sécuriser VulnShop de bout en bout

> ⏱️ 1 à 2 jours · 🎯 Mettre en œuvre tout le cursus sur un seul projet, jusqu'au pipeline 100 % vert en mode strict

## Le contexte

Tu arrives dans une équipe qui maintient VulnShop. Le pipeline est en place mais ne bloque
rien, et l'audit de sécurité est dans deux semaines. Ta mission : **faire passer toutes les
gates en `STRICT=1`**, sans casser l'application, et documenter chaque décision.

## Règles du jeu

1. Travaille sur une branche : `git switch -c securisation`.
2. Une *pull request* par thème (secrets, code, dépendances, conteneur, IaC, pipeline) :
   c'est ainsi qu'on travaille en équipe, et chaque PR est relue par le pipeline.
3. Toute exception (`nosemgrep`, `# nosec`, `.trivyignore`, `checkov:skip`, `hadolint ignore`)
   doit être **justifiée dans un commentaire** et listée dans ton rapport.
4. L'application doit rester fonctionnelle : chaque endpoint répond comme prévu à une
   entrée légitime.
5. Interdiction de « tricher » en désactivant un scanner ou en excluant un dossier entier.

## Critères de réussite

| # | Critère | Vérification |
|---|---|---|
| 1 | Aucun secret dans le code ni dans l'image | `make secrets STRICT=1`, `docker history` |
| 2 | Code sans faille détectée | `make sast STRICT=1 && make bandit STRICT=1` |
| 3 | Dépendances à jour, sans CVE HIGH/CRITICAL | `make sca STRICT=1` |
| 4 | Dockerfile propre, image sans CVE HIGH/CRITICAL corrigeable | `make lint-docker STRICT=1 && make image-scan STRICT=1` |
| 5 | Image non-root, < 250 Mo, fonctionne en `--read-only` | module 05 §2.4 |
| 6 | Infrastructure sans mauvaise configuration | `make iac STRICT=1` |
| 7 | Pipeline durci : actions figées par SHA, permissions minimales | `make ci-audit STRICT=1` |
| 8 | Application en fonctionnement sans alerte bloquante | `make run && make dast STRICT=1` |
| 9 | CI en `STRICT: "1"`, toute verte sur GitHub | onglet *Actions* |
| 10 | `main` protégée, fusion uniquement via PR avec checks obligatoires | *Settings → Branches* |
| 11 | Dependabot configuré | `.github/dependabot.yml` |
| 12 | Le manifeste K8s passe PSA `restricted` sur kind | module 10 §2.2 |

Commande de synthèse :

```bash
make scan-all STRICT=1 && make run && make dast STRICT=1 && echo "🎉 Toutes les gates sont vertes"
```

## Livrable : ton rapport

Crée `RAPPORT.md` à la racine de ta branche :

1. **Synthèse** (5 lignes) : état initial, état final, chiffres clés (nombre de CVE,
   taille d'image, nombre d'alertes par outil avant / après).
2. **Tableau des failles** : `VULN-xx` / outil(s) qui l'ont détectée / correction / PR.
3. **Exceptions acceptées** : chaque exception, sa justification, sa date de réévaluation.
4. **Ce que les outils n'ont pas vu** : failles de conception (authentification, contrôle
   d'accès, journalisation…) et ce que tu proposerais.
5. **Feuille de route** : les trois prochaines améliorations de sécurité que tu
   prioriserais, et pourquoi.

## Bonus

- Signature keyless de l'image et attestation de provenance en CI (module 09 §2.4)
- Ajout de CodeQL au pipeline et comparaison avec Semgrep
- Scan planifié hebdomadaire (`on: schedule`) de l'image publiée
- Authentification sur VulnShop et contrôle d'accès sur `/search` (A01, A07)
- Déploiement de ton image signée sur kind avec une politique Kyverno qui exige la signature

## Corrigé

Une solution de référence est disponible sur la branche **`solution`** du dépôt :

```bash
git fetch origin solution
git diff main origin/solution --stat
git diff main origin/solution -- app/app.py
```

Sur cette branche, le pipeline tourne en `STRICT: "1"` et toutes les gates sont vertes.
Résultats mesurés :

| | `main` (vulnérable) | `solution` |
|---|---|---|
| Semgrep | 14 alertes | 0 |
| Bandit | 11 alertes | 0 (2 exceptions justifiées) |
| CVE dépendances (HIGH/CRITICAL) | 16 | 0 |
| CVE image (HIGH/CRITICAL corrigeables) | ~2 600 | 0 |
| Taille de l'image | 1,58 Go | 195 Mo |
| Hadolint | 7 | 0 (1 exception justifiée) |
| Checkov (échecs) | 59 | 0 (4 exceptions justifiées) |
| zizmor | 18 | 0 |
| ZAP baseline | 13 alertes | 1 avertissement mineur |

> 💡 Ne regarde la solution qu'**après** avoir terminé ta propre version : l'intérêt du
> projet est dans les problèmes que tu rencontres en chemin. Compare ensuite tes choix
> avec ceux de la solution — il y a souvent plusieurs bonnes réponses.

## ✅ Tu as terminé le cursus

Pistes pour continuer :
- **Certifications** : Certified DevSecOps Professional (CDP), CKS (Certified Kubernetes
  Security Specialist), GIAC GCSA
- **Pratique** : OWASP Juice Shop, OWASP WrongSecrets, Kubernetes Goat, CloudGoat
- **Lecture** : OWASP DevSecOps Guideline, OWASP SAMM, NIST SSDF (SP 800-218), SLSA
