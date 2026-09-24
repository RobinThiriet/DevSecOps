# Module 09 — Sécurité de la chaîne d'approvisionnement

> ⏱️ 3 h · 🎯 Garantir que ce qui tourne en production est bien ce que tu as construit, à partir de ce que tu crois

## Objectifs

- Comprendre les attaques de *supply chain* et le cadre **SLSA**
- Figer les dépendances de la CI (actions, images) par empreinte
- Automatiser les mises à jour avec **Dependabot**
- **Signer** une image et vérifier sa signature avec **cosign**
- Connaître les attestations de provenance

## 1. Cours

### 1.1 L'attaque ne vise plus ton code

Pourquoi attaquer une application quand on peut compromettre **ce qu'elle utilise** ?

| Point d'entrée | Exemple de scénario |
|---|---|
| Dépendance | un mainteneur de paquet se fait voler son compte, publie une version piégée |
| *Typosquatting* | `reqeusts` au lieu de `requests` |
| Outil de build / CI | une action GitHub populaire dont un tag est déplacé vers du code malveillant |
| Image de base | une image `latest` remplacée sur le registre |
| Serveur de build | injection dans l'artefact pendant la compilation (cas SolarWinds, 2020) |
| Mainteneur | prise de confiance sur des années, puis porte dérobée (cas xz-utils, 2024) |

### 1.2 SLSA en une page

**SLSA** (*Supply-chain Levels for Software Artifacts*, <https://slsa.dev>) définit des
niveaux de garantie sur la fabrication d'un artefact :

| Niveau | Exigence (simplifiée) |
|---|---|
| Build L1 | la **provenance** existe : un document dit comment l'artefact a été construit |
| Build L2 | la provenance est **signée** par une plateforme de build hébergée |
| Build L3 | le build est **isolé** et la provenance infalsifiable par le projet lui-même |

### 1.3 Les trois réflexes

1. **Figer par empreinte, pas par nom.** Un tag (`v7`, `latest`, `3.13-slim`) est un
   pointeur modifiable. Un SHA de commit ou un digest `sha256:` ne l'est pas.
2. **Mettre à jour automatiquement.** Figer sans mettre à jour, c'est accumuler des CVE.
   Dependabot ou Renovate ouvrent des PR, la CI les valide.
3. **Signer et vérifier.** Signer l'image à la sortie du build ; refuser au déploiement toute
   image non signée (politique d'admission Kubernetes, module 10).

### 1.4 Sigstore / cosign

- **cosign** signe des images (et tout artefact) et stocke la signature dans le registre.
- Mode **à clé** : une paire de clés classique (ce qu'on fait dans le lab, en local).
- Mode **keyless** (recommandé en CI) : pas de clé à gérer. L'identité OIDC du job GitHub
  Actions est certifiée par *Fulcio* et la signature inscrite dans le journal public *Rekor*.
  On vérifie ensuite « signé par le workflow X du dépôt Y ».

## 2. Lab

### 2.1 Figer les actions GitHub par SHA

```bash
make ci-audit       # zizmor : "unpinned-uses"
```

Pour chaque action du workflow, remplace le tag par le SHA de commit correspondant, en
gardant la version en commentaire :

```yaml
- uses: actions/checkout@<sha-de-40-caractères> # v7.0.1
```

Pour trouver le SHA d'un tag :

```bash
git ls-remote --tags https://github.com/actions/checkout.git | grep 'refs/tags/v7.0.1'
```

> ⚠️ Pour un tag *annoté*, prends la ligne `^{}` : c'est le commit, pas l'objet tag.

Objectif : `make ci-audit STRICT=1` passe.

❓ Et les images Docker du [Makefile](../../Makefile) ? Elles sont figées par **tag**.
Quel est le risque résiduel ? Comment le réduire ?

### 2.2 Dependabot

Crée `.github/dependabot.yml` qui surveille chaque semaine :
- les dépendances **pip** de `/app` ;
- l'image de base **docker** de `/app` ;
- les **github-actions** (il sait mettre à jour les SHA et le commentaire de version !).

Documentation :
<https://docs.github.com/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file>

Active aussi *Settings → Code security → Dependabot alerts*. Que remonte GitHub sur la
branche `main` de VulnShop ?

> 💡 Sur `main`, Dependabot va proposer de corriger les dépendances vulnérables du lab.
> Tu peux fermer ces PR, ou ne créer le fichier que sur ta branche de correction.

### 2.3 Signer une image (registre local)

```bash
# 1. Un registre local, et l'image corrigée poussée dedans
docker run -d --name lab-registry -p 127.0.0.1:5005:5000 registry:3
docker tag vulnshop:dev localhost:5005/vulnshop:1.0
docker push localhost:5005/vulnshop:1.0
DIGEST=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' \
         localhost:5005/vulnshop:1.0 | grep localhost:5005)
echo "$DIGEST"

# 2. cosign en conteneur
mkdir -p /tmp/cosign-lab && chmod 777 /tmp/cosign-lab && cd /tmp/cosign-lab
cosign() { docker run --rm --network host -v "$PWD:/w" -w /w -e COSIGN_PASSWORD \
           ghcr.io/sigstore/cosign/cosign:v3.1.3 "$@"; }
export COSIGN_PASSWORD='choisis-un-mot-de-passe'

# 3. Clés, signature, vérification
cosign generate-key-pair
cosign sign --yes --key cosign.key --use-signing-config=false --tlog-upload=false "$DIGEST"
cosign verify --key cosign.pub --insecure-ignore-tlog=true "$DIGEST"
```

Les options `--tlog-upload=false` / `--insecure-ignore-tlog` désactivent le journal public
Rekor : acceptable **uniquement** pour un lab local hors ligne.

Puis :
1. Pousse une autre image sous le tag `localhost:5005/vulnshop:evil` et essaie de la vérifier.
2. Pourquoi signe-t-on le **digest** et pas le tag `:1.0` ?
3. Où est stockée la signature ? (indice : `curl -s localhost:5005/v2/vulnshop/tags/list`)
4. Nettoyage : `docker rm -f lab-registry`. Ne commite **jamais** `cosign.key`.

### 2.4 Pour aller plus loin : keyless et provenance en CI

Sur ta branche de correction, ajoute un job qui publie l'image sur `ghcr.io`, la signe en
keyless et génère une attestation de provenance :

```yaml
  publish:
    needs: [container]
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write        # pousser sur ghcr.io
      id-token: write        # obtenir un jeton OIDC pour la signature keyless
      attestations: write    # publier l'attestation de provenance
```

Outils : `docker/login-action`, `docker/build-push-action`, `sigstore/cosign-installer`
puis `cosign sign --yes ghcr.io/...@${DIGEST}`, et `actions/attest-build-provenance`.
Vérification : `gh attestation verify oci://ghcr.io/<toi>/vulnshop@<digest> --owner <toi>`.

## 3. Corrigés

<details>
<summary>2.1 — Actions figées</summary>

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
- uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
- uses: github/codeql-action/upload-sarif@1c5b675653bb5c22dbe9b12b556ec555138e09fd # v4.38.1
```

(SHA valides au moment de la rédaction ; vérifie-les toi-même, c'est l'exercice.)

Pour les images du Makefile, un tag de version (`aquasec/trivy:0.67.2`) est bien meilleur
que `latest`, mais reste modifiable par l'éditeur ou par un attaquant qui aurait compromis
son compte. Solution : figer par digest (`aquasec/trivy:0.67.2@sha256:...`) et laisser
Dependabot (`package-ecosystem: docker`) ou Renovate proposer les mises à jour.
</details>

<details>
<summary>2.2 — dependabot.yml</summary>

```yaml
version: 2
updates:
  - package-ecosystem: pip
    directory: /app
    schedule:
      interval: weekly
    groups:
      python:
        patterns: ["*"]

  - package-ecosystem: docker
    directory: /app
    schedule:
      interval: weekly

  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    groups:
      actions:
        patterns: ["*"]
```

Les `groups` regroupent les mises à jour en une seule PR par écosystème : moins de bruit.
</details>

<details>
<summary>2.3 — Signature</summary>

1. `no signatures found` : la vérification échoue, l'image serait refusée au déploiement.
2. Un tag peut être déplacé vers une autre image après la signature ; le digest est
   l'empreinte du contenu, il ne peut désigner qu'une seule image.
3. Dans le **même dépôt du registre**, sous un tag spécial dérivé du digest :
   `sha256-<digest>` avec cosign v3 (`sha256-<digest>.sig` avec cosign v2). La signature
   voyage avec l'image, sans infrastructure supplémentaire.
</details>

## ✅ Checklist

- [ ] `make ci-audit STRICT=1` passe (actions figées par SHA)
- [ ] J'ai un `dependabot.yml` pour pip, docker et github-actions
- [ ] J'ai signé et vérifié une image, et vu une image non signée refusée
- [ ] Je sais expliquer SLSA Build L1 → L3

➡️ [Module 10 — Kubernetes & runtime](../10-kubernetes-runtime/README.md)
