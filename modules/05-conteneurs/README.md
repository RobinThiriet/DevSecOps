# Module 05 — Sécurité des conteneurs

> ⏱️ 3 h · 🎯 Construire une image minimale, non-root, sans CVE, et la lancer durcie

## Objectifs

- Connaître les bonnes pratiques d'écriture d'un Dockerfile
- Lint avec **Hadolint**, scan d'image avec **Trivy**
- Réduire la surface d'attaque : image minimale, multi-étapes, non-root
- Durcir l'exécution : lecture seule, capabilities, limites de ressources

## 1. Cours

### 1.1 Un conteneur n'est pas une VM

Un conteneur partage le **noyau** de l'hôte. L'isolation repose sur des mécanismes Linux
(namespaces, cgroups, capabilities, seccomp). Conséquences :
- `root` dans le conteneur = UID 0 sur le noyau de l'hôte, seulement « bridé » ;
- une faille noyau ou une mauvaise option (`--privileged`, montage du socket Docker)
  peut suffire à sortir du conteneur ;
- **chaque paquet** présent dans l'image est un outil de plus pour un attaquant qui y
  entre, et une CVE de plus à gérer.

### 1.2 Les règles d'un bon Dockerfile

| # | Règle | Pourquoi |
|---|---|---|
| 1 | Image de base **minimale** (`-slim`, `alpine`, *distroless*, *chainguard*) | moins de paquets = moins de CVE et d'outils pour l'attaquant |
| 2 | Version figée, idéalement **par digest** (`@sha256:...`) | reproductible, un tag peut être réécrit |
| 3 | **Multi-étapes** : on compile dans une étape, on copie le résultat dans une image propre | les outils de build ne partent pas en production |
| 4 | `USER` non-root avec un UID élevé | limite l'impact d'une compromission |
| 5 | `COPY` plutôt que `ADD`, `.dockerignore` strict | pas de fichiers inattendus (`.git`, `.env`…) dans l'image |
| 6 | **Aucun secret** dans `ENV`, `ARG` ou une couche | `docker history` et chaque couche les révèlent |
| 7 | `--no-install-recommends`, nettoyage du cache apt, `--no-cache-dir` pip | taille, surface |
| 8 | `CMD`/`ENTRYPOINT` en notation JSON | signaux correctement transmis (arrêt propre) |
| 9 | `HEALTHCHECK` | l'orchestrateur sait si l'app est vivante |
| 10 | Un serveur de production (gunicorn…), pas le serveur de dev | performances, pas de débogueur |

### 1.3 Durcir l'exécution

Même une bonne image se lance mal. Options clés de `docker run` (et leur équivalent
Kubernetes, module 06) :

| Option | Effet |
|---|---|
| `--read-only` (+ `--tmpfs /tmp`) | système de fichiers en lecture seule |
| `--cap-drop ALL` | retire toutes les *capabilities* Linux |
| `--security-opt no-new-privileges` | interdit l'élévation via setuid |
| `--memory`, `--pids-limit`, `--cpus` | limite l'impact d'un déni de service |
| `-p 127.0.0.1:...` | n'expose le port que localement |
| **jamais** `--privileged`, ni `-v /var/run/docker.sock:...` | équivalent à donner root sur l'hôte |

## 2. Lab

### 2.1 Auditer le Dockerfile existant

```bash
make lint-docker
```

Pour chaque alerte Hadolint, retrouve la règle du tableau 1.2 correspondante.
❓ Hadolint ne dit rien sur `USER` ni sur l'image `python:3.7`. Pourquoi ? Qu'est-ce qu'un
linter ne peut pas savoir ?

### 2.2 Mesurer le problème

```bash
make image-scan
docker images vulnshop:dev          # taille ?
docker history vulnshop:dev         # que vois-tu dans les couches ?
docker run --rm vulnshop:dev id     # quel utilisateur ?
docker run --rm vulnshop:dev env | grep -i pass
```

Note : nombre de CVE HIGH/CRITICAL, taille de l'image, utilisateur, secret visible ?

### 2.3 Réécrire le Dockerfile

Sur ta branche de correction (avec les dépendances à jour du module 04), réécris
[app/Dockerfile](../../app/Dockerfile) en appliquant **toutes** les règles du tableau 1.2.
Objectifs mesurables :

- [ ] `make lint-docker STRICT=1` passe
- [ ] `make image-scan STRICT=1` passe (0 HIGH/CRITICAL corrigeable)
- [ ] L'image fait moins de 250 Mo
- [ ] `docker run --rm vulnshop:dev id` n'affiche pas `root`
- [ ] Aucun secret dans `docker history`

> 💡 Si Trivy trouve encore des CVE dans `pip` lui-même : pip sert-il à quelque chose une
> fois les dépendances installées ?

### 2.4 Lancer le conteneur durci

```bash
docker run -d --name vs-hard -p 127.0.0.1:5001:5000 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --pids-limit 100 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  vulnshop:dev
curl "http://127.0.0.1:5001/search?q=alice"
docker inspect vs-hard --format '{{.State.Health.Status}}'   # après ~30 s
docker rm -f vs-hard
```

❓ L'app fonctionne-t-elle encore ? Si non, qu'écrivait-elle sur le disque, et où ?

### 2.5 Pour aller plus loin

- Essaie une image **distroless** (`gcr.io/distroless/python3-debian12`) : plus de shell,
  plus de gestionnaire de paquets. Qu'est-ce que ça change pour le débogage ?
- Compare le nombre de CVE entre `python:3.13`, `python:3.13-slim` et `python:3.13-alpine`.

## 3. Corrigé

<details>
<summary>2.1 — Les limites du linter</summary>

Hadolint analyse le **texte** du Dockerfile. Il ne sait pas que `python:3.7` est en fin de
vie ni combien de CVE l'image contient (c'est le rôle du scan d'image), et l'absence de
`USER` ne relève que d'une règle optionnelle. Linter et scanner sont complémentaires.
</details>

<details>
<summary>2.3 — Dockerfile corrigé</summary>

```dockerfile
# syntax=docker/dockerfile:1
# Image de base figée par digest : reproductible, et un changement d'image est visible en revue.
ARG PYTHON_IMAGE=python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0

# --- Étape 1 : installation des dépendances ----------------------------------
FROM ${PYTHON_IMAGE} AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Étape 2 : image d'exécution minimale ------------------------------------
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# - ping est nécessaire à /ping (pas de version figée : on suit la branche stable
#   Debian et l'image est reconstruite régulièrement)
# - pip est retiré : inutile à l'exécution, il embarque ses propres dépendances vulnérables
# - utilisateur dédié, sans shell ni home
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall -y pip \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY --from=build /install /usr/local
WORKDIR /app
COPY app.py .

USER 10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/')"]

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "app:app"]
```

Et `app/.dockerignore` en liste blanche :

```
*
!app.py
!requirements.txt
```

Résultats mesurés sur la branche `solution` :

| | Avant | Après |
|---|---|---|
| CVE HIGH/CRITICAL corrigeables | ~2 600 | **0** |
| Taille | 1,58 Go | **195 Mo** |
| Utilisateur | root | UID 10001 |
| Alertes Hadolint | 7 | 0 (1 exception justifiée) |

Le digest de l'image de base se récupère avec
`docker buildx imagetools inspect python:3.13-slim` ; Dependabot (module 09) saura le mettre
à jour automatiquement.
</details>

<details>
<summary>2.4 — Lecture seule</summary>

La version vulnérable écrit sa base SQLite **à côté du code** (`/app/vulnshop.db`) : avec
`--read-only`, elle plante. La version corrigée écrit dans le répertoire temporaire
(`/tmp`, monté en `tmpfs`) ou dans `DATABASE_PATH`. Principe : le code est immuable, seules
les données vont dans un emplacement dédié et explicitement inscriptible.
</details>

## ✅ Checklist

- [ ] Je sais pourquoi `--privileged` et le socket Docker sont interdits
- [ ] Mon image passe Hadolint et Trivy en `STRICT=1`
- [ ] Mon image tourne en non-root, en lecture seule, sans capabilities

➡️ [Module 06 — Infrastructure as Code](../06-iac/README.md)
