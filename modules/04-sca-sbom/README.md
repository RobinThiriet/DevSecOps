# Module 04 — SCA & SBOM : sécuriser ses dépendances

> ⏱️ 2 h 30 · 🎯 Savoir de quoi est fait son logiciel et quelles vulnérabilités il hérite

## Objectifs

- Comprendre CVE, CVSS, EPSS et KEV, et **prioriser** plutôt que tout corriger
- Scanner les dépendances avec **Trivy**
- Générer un **SBOM** avec **Syft** et le scanner avec **Grype**
- Mettre à jour les dépendances de VulnShop proprement

## 1. Cours

### 1.1 Ton code est minoritaire

Dans une application moderne, 80 à 90 % du code exécuté vient de dépendances
(bibliothèques, et **leurs** dépendances : les dépendances *transitives*). Une faille dans
l'une d'elles est une faille dans ton application — voir Log4Shell (2021).

### 1.2 Le vocabulaire

| Terme | Signification |
|---|---|
| **CVE** | Identifiant unique d'une vulnérabilité publique (`CVE-2020-14343`) |
| **GHSA** | Identifiant GitHub Advisory, souvent lié à une CVE |
| **CVSS** | Score de **gravité** théorique de 0 à 10 (LOW / MEDIUM / HIGH / CRITICAL) |
| **EPSS** | **Probabilité** qu'une CVE soit exploitée dans les 30 jours (0–100 %) |
| **KEV** | Catalogue CISA des vulnérabilités **exploitées activement**, confirmé |
| **Fixed version** | Première version corrigée — s'il n'y en a pas, on parle de CVE *unfixed* |

> 💡 **Prioriser** : une CVE CRITICAL avec EPSS 0,1 % dans une fonction que tu n'appelles
> jamais est souvent moins urgente qu'une HIGH présente dans KEV et exposée sur Internet.
> Ordre raisonnable : **KEV → EPSS élevé → CVSS élevé → le reste**.

### 1.3 Épingler ses dépendances

| Fichier | Contenu | Reproductible ? |
|---|---|---|
| `flask` | la dernière version au moment du build | ❌ |
| `flask>=2.0` | une plage | ❌ |
| `Flask==3.1.3` | une version exacte, mais pas les transitives | ⚠️ |
| lockfile (`pip-compile`, `poetry.lock`, `uv.lock`) avec **hashes** | tout l'arbre, vérifié | ✅ |

Épingler ne suffit pas : il faut aussi **mettre à jour régulièrement** (Dependabot /
Renovate, module 09). Une version figée en 2018 est parfaitement reproductible… et
parfaitement vulnérable.

### 1.4 Le SBOM

Un **SBOM** (*Software Bill of Materials*) est l'inventaire complet de ce que contient un
logiciel : paquets, versions, licences, empreintes. Deux formats standards : **CycloneDX**
(OWASP) et **SPDX** (Linux Foundation). Pourquoi c'est utile :

- Le jour où une nouvelle CVE sort, tu sais **en quelques secondes** si tu es concerné,
  sans reconstruire quoi que ce soit.
- C'est une exigence réglementaire croissante (Executive Order US 14028, **Cyber
  Resilience Act** européen).
- Le **VEX** (*Vulnerability Exploitability eXchange*) complète le SBOM en déclarant
  « cette CVE ne nous affecte pas, et voici pourquoi ».

## 2. Lab

### 2.1 Scanner les dépendances

```bash
make sca
```

1. Combien de vulnérabilités HIGH et CRITICAL ?
2. Pour la CVE CRITICAL de PyYAML, lis la fiche (lien dans le rapport). Quel est le lien
   avec la faille `VULN-06` trouvée par le SAST au module 03 ?
3. Relance avec toutes les sévérités : `make sca SEVERITY=LOW,MEDIUM,HIGH,CRITICAL`.

### 2.2 Générer et exploiter un SBOM

```bash
make sbom            # écrit reports/sbom.cdx.json
```

1. Combien de composants contient l'image ? (indice : `python3 -c "import json;
   print(len(json.load(open('reports/sbom.cdx.json'))['components']))"`)
2. Pourquoi y en a-t-il autant alors que `requirements.txt` ne liste que 9 paquets ?
3. Scanne le SBOM, sans l'image :
   ```bash
   make sbom-scan
   ```
   Repère les colonnes **EPSS** et **RISK**, et les lignes marquées `(kev)`.
   Quelles sont les 3 vulnérabilités que tu traiterais en premier ?

### 2.3 Licences

Les dépendances apportent aussi des **obligations juridiques**.

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache \
  aquasec/trivy:0.67.2 image --scanners license --severity HIGH,CRITICAL vulnshop:dev
```

❓ Que signifie la catégorie `restricted` ? Pourquoi une entreprise qui distribue son
logiciel s'en préoccupe-t-elle ?

### 2.4 Accepter un risque… proprement

Crée un fichier `app/.trivyignore` pour ignorer **une** CVE que tu juges non exploitable
dans le contexte de VulnShop :

```
# CVE-XXXX-YYYY : <pourquoi elle ne nous concerne pas>
# Décision : <ton nom>, <date> — à réévaluer le <date + 3 mois>
CVE-XXXX-YYYY
```

❓ Pourquoi une date de réévaluation est-elle indispensable ?

### 2.5 Mettre à jour VulnShop

Sur ta branche de correction, mets à jour `app/requirements.txt` vers des versions
actuelles et **épingle aussi les dépendances transitives**. Supprime ce qui n'est pas utilisé.
Relance `make sca STRICT=1` jusqu'au vert, puis vérifie que l'app fonctionne encore
(`make run`) : une mise à jour majeure peut casser l'API (Flask 0.12 → 3.x).

## 3. Corrigés

<details>
<summary>2.1 — PyYAML</summary>

`CVE-2020-14343` : `yaml.load` avec le `FullLoader` permet l'exécution de code arbitraire
(correctif incomplet d'une CVE précédente). Le SCA dit « ta version est vulnérable », le
SAST dit « tu utilises la fonction dangereuse » : les deux ensemble confirment que la faille
est **atteignable**. C'est exactement ce genre de corrélation qui permet de prioriser.
</details>

<details>
<summary>2.2 — SBOM</summary>

L'image `python:3.7` complète contient des centaines de paquets Debian (compilateurs,
bibliothèques graphiques, outils…) en plus des paquets Python. Chaque paquet est une
surface d'attaque potentielle : c'est l'argument principal pour les images minimales du
module 05. Les vulnérabilités marquées `(kev)` sont à traiter en premier, quel que soit
leur score CVSS.
</details>

<details>
<summary>2.3 — Licences</summary>

`restricted` regroupe typiquement les licences à fort *copyleft* (GPL…) : si tu
**distribues** un logiciel qui les intègre, tu peux être tenu d'en publier le code source.
Pour un service web interne le risque est plus faible, mais les équipes juridiques veulent
le savoir. D'où l'intérêt d'automatiser ce contrôle.
</details>

<details>
<summary>2.4 — Pourquoi une date de réévaluation</summary>

Un contexte change : la fonction « jamais appelée » l'est dans la version suivante, un
exploit public sort, la CVE entre dans KEV. Une exception sans date devient un angle mort
permanent. Trivy accepte aussi un format YAML (`.trivyignore.yaml`) avec un champ
`expired_at` qui réactive automatiquement l'alerte.
</details>

<details>
<summary>2.5 — requirements.txt à jour</summary>

```
blinker==1.9.0
click==8.5.0
Flask==3.1.3
gunicorn==26.2.0
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.3
PyYAML==6.0.3
Werkzeug==3.1.8
```

`requests` et `urllib3` ont été supprimés : l'app ne les utilise pas. **La dépendance la
plus sûre est celle qu'on n'a pas.** `gunicorn` est ajouté pour remplacer le serveur de
développement (module 05). Pour aller plus loin : générer ce fichier avec
`pip-compile --generate-hashes` et installer avec `pip install --require-hashes`.
</details>

## ✅ Checklist

- [ ] Je sais expliquer la différence entre CVSS, EPSS et KEV
- [ ] J'ai généré un SBOM CycloneDX et je l'ai scanné sans l'image
- [ ] J'ai une exception `.trivyignore` justifiée et datée
- [ ] Sur ma branche, `make sca STRICT=1` passe et l'app fonctionne

➡️ [Module 05 — Sécurité des conteneurs](../05-conteneurs/README.md)
