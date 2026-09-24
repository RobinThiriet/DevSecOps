# Module 07 — Pipeline CI/CD DevSecOps

> ⏱️ 3 h · 🎯 Automatiser tous les contrôles à chaque commit, et bloquer ce qui doit l'être

## Objectifs

- Comprendre ce qu'est une *security gate* et où la placer
- Lire et modifier le pipeline GitHub Actions du dépôt
- Visualiser les résultats dans l'onglet **Security → Code scanning**
- Sécuriser le pipeline lui-même (permissions, identifiants)
- Protéger la branche `main`

## 1. Cours

### 1.1 Principes d'un pipeline DevSecOps

| Principe | Concrètement |
|---|---|
| **Feedback rapide** | les scans rapides (secrets, SAST) d'abord, en parallèle ; le DAST (lent) après |
| **Mêmes outils en local et en CI** | ici, chaque job appelle une cible `make` |
| **Gate progressive** | commencer en mode « rapport », puis bloquer sur CRITICAL, puis HIGH… |
| **Résultats centralisés** | format **SARIF** → onglet *Code scanning*, suivi des alertes dans le temps |
| **Le pipeline est une cible** | il a accès au code, aux secrets, parfois à la prod : moindre privilège |

### 1.2 Bloquer ou informer ?

Un pipeline qui bloque sur tout, dès le premier jour, sera contourné. Stratégie réaliste :

1. **Semaine 1** : tous les scans en mode rapport (`STRICT=0`), on mesure.
2. **Bloquer les nouveaux problèmes** sur les PR, traiter la dette existante à part.
3. Monter progressivement le niveau d'exigence : CRITICAL → HIGH → …

### 1.3 Sécuriser GitHub Actions

| Risque | Protection |
|---|---|
| `GITHUB_TOKEN` trop puissant | `permissions:` explicites, au niveau le plus bas possible |
| Token git laissé sur le disque du runner | `persist-credentials: false` sur `actions/checkout` |
| Action tierce compromise | la figer par **SHA de commit** (module 09) |
| Injection via un titre de PR / nom de branche | ne jamais interpoler `${{ github.event.* }}` dans un `run:`, passer par `env:` |
| `pull_request_target` | s'exécute avec les secrets du dépôt sur du code de fork : à éviter |
| Secrets dans les logs | secrets GitHub (masqués automatiquement), jamais d'`echo` |

**zizmor** est un analyseur statique dédié aux workflows GitHub Actions : `make ci-audit`.

### 1.4 Protection de branche

Même le meilleur pipeline ne sert à rien si on peut pousser directement sur `main`.
*Settings → Branches → Add rule* (ou *Rulesets*) :
- exiger une *pull request* avant fusion ;
- exiger que les **status checks** (les jobs du pipeline) passent ;
- interdire le *force push*.

## 2. Lab

### 2.1 Découvrir le pipeline

1. Lis [.github/workflows/devsecops.yml](../../.github/workflows/devsecops.yml).
   Pour chaque job : quelle cible `make` ? quelles permissions ?
2. Sur GitHub, onglet **Actions** : ouvre la dernière exécution. Tous les jobs sont verts…
   alors que l'app est truffée de failles. Pourquoi ?
3. Onglet **Security → Code scanning** : combien d'alertes ? Filtre par outil
   (`tool:semgrep`, `tool:checkov`…). Ouvre-en une : que t'apporte cette vue par rapport au
   terminal ?

### 2.2 Activer les gates

Sur une branche `feat/gates` :
1. Passe `STRICT: "1"` dans le workflow.
2. Pousse et ouvre une *pull request*. Quels jobs échouent ?
3. Ajoute la dépendance `needs:` pour que le job `dast` ne tourne que si **tous** les scans
   statiques sont verts, et seulement hors *pull request*.

### 2.3 Auditer le pipeline lui-même

```bash
make ci-audit
```

1. Quels types de problèmes zizmor remonte-t-il ?
2. Corrige `artipacked` (identifiants persistés) sur tous les `actions/checkout`.
3. Mets `permissions: {}` au niveau du workflow et donne à chaque job **uniquement** ce dont
   il a besoin. Le job `container` a-t-il besoin de `security-events: write` ?
4. Garde `unpinned-uses` pour le module 09.

### 2.4 Protéger `main`

Configure une règle de protection sur `main` : PR obligatoire, jobs `secrets`, `sast`, `sca`
et `iac` obligatoires. Vérifie qu'un `git push origin main` direct est refusé.

> ⚠️ Tant que VulnShop n'est pas corrigée, un pipeline strict bloquera tout. C'est
> l'objectif du [projet final](../11-projet-final/README.md) : fusionner ta branche de
> correction avec toutes les gates au vert.

### 2.5 Pour aller plus loin

- Un scan de *PR* ne devrait signaler que les **nouveaux** problèmes. Comment faire avec
  Semgrep (`--baseline-commit`) ?
- Ajoute un job CodeQL (`github/codeql-action/init` + `analyze`) : gratuit sur un dépôt
  public. Trouve-t-il des failles que Semgrep et Bandit ont ratées ?
- Planifie un scan hebdomadaire (`on: schedule`) : une image sans CVE aujourd'hui en aura
  demain, sans que tu aies changé une ligne de code.

## 3. Corrigés

<details>
<summary>2.1 — Pourquoi tout est vert ?</summary>

Parce que `STRICT: "0"` : chaque cible `make` affiche les problèmes puis sort avec le code
`0`. Les résultats sont bien publiés (SARIF) mais rien ne bloque. C'est le mode « on
mesure avant de bloquer » du §1.2.
</details>

<details>
<summary>2.2 / 2.3 — Workflow corrigé</summary>

Le fichier complet est sur la branche `solution`. Points clés :

```yaml
permissions: {}          # rien par défaut

env:
  STRICT: "1"

jobs:
  sast:
    permissions:
      contents: read
      security-events: write    # uniquement les jobs qui publient du SARIF
    steps:
      - uses: actions/checkout@<sha> # v7.0.1
        with:
          persist-credentials: false
      # ...

  dast:
    needs: [secrets, sast, sca, iac, container]
    if: github.event_name != 'pull_request'
```

Le job `container` ne publie pas de SARIF : `contents: read` suffit.
</details>

<details>
<summary>2.5 — Ne signaler que les nouveaux problèmes</summary>

```bash
semgrep scan --baseline-commit "$(git merge-base origin/main HEAD)" ...
```

Semgrep compare avec l'état de la branche cible et ne remonte que ce que la PR introduit.
Le checkout doit contenir l'historique (`fetch-depth: 0`). L'onglet *Code scanning* fait
aussi cette distinction automatiquement dans les PR.
</details>

## ✅ Checklist

- [ ] J'ai vu les alertes dans *Security → Code scanning*
- [ ] Mon pipeline bloque en `STRICT=1` et le DAST dépend des scans statiques
- [ ] `make ci-audit` ne remonte plus que `unpinned-uses`
- [ ] `main` est protégée

➡️ [Module 08 — DAST](../08-dast/README.md)
