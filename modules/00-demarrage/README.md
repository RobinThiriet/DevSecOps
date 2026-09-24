# Module 00 — Démarrage

> ⏱️ 45 min · 🎯 Avoir un environnement fonctionnel et comprendre l'organisation du dépôt

## Objectifs

- Installer les prérequis
- Comprendre comment le dépôt est organisé
- Lancer l'application cible **VulnShop** et le premier scan

## 1. Prérequis

| Outil | Pourquoi | Vérification |
|---|---|---|
| Git | versionner, et plus tard fouiller l'historique | `git --version` |
| Docker | **tous** les outils de sécurité tournent en conteneur | `docker run --rm hello-world` |
| make | raccourcis pour chaque scan | `make --version` |
| curl | interroger l'app depuis le terminal | `curl --version` |

Sous Debian/Ubuntu/WSL : `sudo apt install -y git make curl`, puis Docker via
<https://docs.docker.com/engine/install/>.

> 💡 **Pourquoi tout passe par Docker ?** Pas de « ça marche sur ma machine » : la version de
> chaque outil est figée dans le [Makefile](../../Makefile), et la CI lance exactement les mêmes
> commandes que toi.

## 2. Visite du dépôt

```
app/          VulnShop : l'application Flask volontairement vulnérable (la cible)
infra/        Terraform + Kubernetes volontairement mal configurés
modules/      les cours et les labs (tu es ici)
scripts/      scripts de préparation des labs
.github/      le pipeline CI DevSecOps
Makefile      toutes les commandes : `make help`
```

Chaque faille est repérée dans le code par un commentaire `VULN-xx`, `IAC-xx` ou `K8S-xx`.
**Ne les lis pas encore** : l'intérêt des modules suivants est de voir ce que les outils
trouvent… et ce qu'ils ratent.

## 3. Lancer VulnShop

```bash
make help         # liste toutes les commandes
make run          # construit l'image et lance l'app sur http://127.0.0.1:5000
make logs         # (Ctrl+C pour quitter)
make stop         # quand tu as fini
```

L'app n'écoute que sur `127.0.0.1` : elle n'est pas exposée à ton réseau. Garde ça comme ça,
et ne la déploie jamais ailleurs que sur ta machine.

## 4. Lab — Premier scan

1. Ouvre <http://127.0.0.1:5000> et parcours les différentes pages.
2. Lance ton premier scan de sécurité :
   ```bash
   make sast
   ```
3. Réponds dans ton [journal de bord](../../PROGRESSION.md) :
   - Combien de problèmes Semgrep remonte-t-il ?
   - Quelles catégories de failles reconnais-tu (OWASP Top 10) ?
   - Le scan a « réussi » alors qu'il a trouvé des failles. Relance avec `make sast STRICT=1`
     et regarde le code de retour (`echo $?`). Pourquoi cette différence est-elle
     fondamentale pour une CI ?

## ✅ Checklist

- [ ] `make run` affiche « VulnShop écoute sur http://127.0.0.1:5000 »
- [ ] `make sast` produit `reports/semgrep.sarif`
- [ ] J'ai compris la différence entre mode apprentissage et `STRICT=1`

➡️ [Module 01 — Fondamentaux](../01-fondamentaux/README.md)
