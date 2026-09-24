# Module 01 — Fondamentaux du DevSecOps

> ⏱️ 2 h · 🎯 Comprendre le « pourquoi » avant le « comment »

## Objectifs

- Définir le DevSecOps et le *shift-left*
- Situer chaque type d'outil dans le cycle de vie logiciel
- Connaître l'OWASP Top 10 et faire une première modélisation des menaces (STRIDE)

## 1. Cours

### 1.1 Du DevOps au DevSecOps

Le DevOps a raccourci le cycle « écrire → livrer » de plusieurs mois à quelques minutes.
Une équipe sécurité qui audite *à la fin* devient alors soit un goulot d'étranglement, soit
contournée. Le DevSecOps répond à ça :

- **La sécurité est la responsabilité de toute l'équipe**, pas d'un service à part.
- **Automatiser** les contrôles pour qu'ils tournent à chaque commit, sans humain.
- **Shift-left** : détecter le plus tôt possible. Une faille trouvée dans l'IDE coûte quelques
  minutes ; la même trouvée en production coûte un incident.

### 1.2 Où agit chaque outil ?

```
 Code ──► Commit ──► Build ──► Test ──► Release ──► Deploy ──► Run
  │         │          │         │         │           │         │
  IDE     pre-commit  SAST      DAST     signature    IaC /     monitoring
  lint    secrets     SCA               SBOM         policies  runtime (Falco)
                      image scan                     admission
  └──── module 03 ──┘ └ 02,03,04,05 ┘ └ 08 ┘ └── 09 ──┘ └ 06,10 ┘  └ 10 ┘
```

| Sigle | Nom | Question posée | Outil du lab |
|---|---|---|---|
| **Secrets** | Secret scanning | Y a-t-il des identifiants dans le code ou l'historique ? | Gitleaks |
| **SAST** | Static App. Security Testing | Le code source contient-il des motifs dangereux ? | Semgrep |
| **SCA** | Software Composition Analysis | Mes dépendances ont-elles des CVE connues ? | Trivy fs |
| **SBOM** | Software Bill of Materials | De quoi mon logiciel est-il composé ? | Syft |
| **Container scan** | — | Mon image embarque-t-elle des paquets vulnérables ? | Trivy image, Hadolint |
| **IaC scan** | Infrastructure as Code | Mon infra est-elle mal configurée *avant* d'exister ? | Checkov |
| **DAST** | Dynamic App. Security Testing | L'app qui tourne réagit-elle mal à des requêtes piégées ? | OWASP ZAP |

> ⚠️ Aucun outil ne voit tout. SAST ne voit pas la config du serveur, DAST ne voit pas le
> code, SCA ne voit pas *ton* code. C'est la **combinaison** qui fait la défense en profondeur.

### 1.3 Vrais et faux positifs

| | L'outil alerte | L'outil n'alerte pas |
|---|---|---|
| **Faille réelle** | ✅ Vrai positif | ❌ **Faux négatif** (le plus dangereux) |
| **Pas de faille** | 😩 Faux positif (fatigue des alertes) | ✅ Vrai négatif |

Un pipeline qui bloque sur des faux positifs sera désactivé par l'équipe en une semaine.
Savoir **trier, ignorer proprement (avec justification) et régler les seuils** fait partie
du métier.

### 1.4 OWASP Top 10 (2021)

| # | Catégorie | Présent dans VulnShop ? |
|---|---|---|
| A01 | Broken Access Control | à toi de voir |
| A02 | Cryptographic Failures | oui |
| A03 | Injection | oui (plusieurs) |
| A04 | Insecure Design | oui |
| A05 | Security Misconfiguration | oui |
| A06 | Vulnerable and Outdated Components | oui |
| A07 | Identification and Authentication Failures | à toi de voir |
| A08 | Software and Data Integrity Failures | oui |
| A09 | Security Logging and Monitoring Failures | oui |
| A10 | Server-Side Request Forgery | non |

Référence : <https://owasp.org/Top10/>

### 1.5 Modélisation des menaces : STRIDE

Avant d'outiller, on se demande *ce qui peut mal tourner*. STRIDE donne six questions :

| Lettre | Menace | Propriété violée | Exemple de question |
|---|---|---|---|
| **S** | Spoofing | Authentification | Quelqu'un peut-il se faire passer pour un autre ? |
| **T** | Tampering | Intégrité | Des données peuvent-elles être modifiées sans contrôle ? |
| **R** | Repudiation | Traçabilité | Peut-on nier avoir fait une action (pas de logs) ? |
| **I** | Information disclosure | Confidentialité | Des données fuient-elles (erreurs, logs, réponses) ? |
| **D** | Denial of service | Disponibilité | Peut-on rendre l'app indisponible ? |
| **E** | Elevation of privilege | Autorisation | Peut-on obtenir plus de droits que prévu ? |

## 2. Lab — Modéliser VulnShop

1. Lis [app/app.py](../../app/app.py) (les commentaires `VULN-xx` sont autorisés cette fois).
2. Dessine le flux de données : `Utilisateur → Flask → SQLite / shell / désérialiseurs`.
   Marque les **frontières de confiance** (là où une donnée non fiable entre).
3. Remplis le tableau dans [PROGRESSION.md](../../PROGRESSION.md) : pour chaque endpoint,
   quelle(s) lettre(s) STRIDE s'applique(nt), et quelle catégorie OWASP ?
4. Pour chaque faille, devine **quel outil** du tableau 1.2 devrait la détecter. Tu vérifieras
   tes hypothèses dans les modules suivants.

<details>
<summary>💡 Corrigé indicatif</summary>

| Endpoint / élément | STRIDE | OWASP | Outil attendu |
|---|---|---|---|
| `/search` (SQL concaténé) | T, I, E | A03 | SAST, DAST actif |
| `/hello` (template construit avec l'entrée) | T, I, E | A03 | SAST, DAST |
| `/ping` (`shell=True`) | T, E | A03 | SAST |
| `/import` (`yaml.Loader`) | T, E | A08 | SAST |
| `/session` (`pickle`) | T, E | A08 | SAST (… en théorie) |
| MD5 pour les mots de passe | I | A02 | SAST |
| `SECRET_KEY` codé en dur | S, I | A02/A05 | Secrets, SAST |
| `debug=True` | I, E | A05 | SAST, DAST |
| Dépendances de 2018 | tout | A06 | SCA |
| Aucun log d'accès/sécurité | R | A09 | *aucun outil* → revue humaine |
| Aucune authentification | S, E | A01/A07 | *aucun outil* → conception |

Les deux dernières lignes sont importantes : ce sont des failles de **conception**, qu'aucun
scanner ne trouvera. D'où l'intérêt de la modélisation des menaces.
</details>

## ✅ Checklist

- [ ] Je sais expliquer le shift-left à un collègue en 2 minutes
- [ ] Je sais placer SAST, SCA, DAST, IaC scan dans le cycle de vie
- [ ] J'ai rempli ma matrice STRIDE de VulnShop

➡️ [Module 02 — Gestion des secrets](../02-secrets/README.md)
