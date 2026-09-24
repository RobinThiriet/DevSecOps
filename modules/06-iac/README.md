# Module 06 — Infrastructure as Code (Terraform & Kubernetes)

> ⏱️ 3 h · 🎯 Trouver les mauvaises configurations *avant* que l'infrastructure existe

## Objectifs

- Comprendre pourquoi la mauvaise configuration est la 1ʳᵉ cause d'incidents cloud
- Scanner Terraform et Kubernetes avec **Checkov** (et comparer avec **Trivy config**)
- Écrire une politique personnalisée (*policy as code*)
- Gérer les exceptions de façon traçable
- Corriger l'infrastructure de VulnShop

> ℹ️ Aucun compte cloud n'est nécessaire : on ne fait **jamais** `terraform apply` dans ce
> lab. L'analyse est purement statique.

## 1. Cours

### 1.1 Pourquoi scanner l'IaC ?

Avec l'IaC, l'infrastructure est du code : elle se relit, se versionne… et **s'analyse**.
Un bucket S3 public ou un port SSH ouvert à Internet se voit dans une *pull request*,
avant même d'exister. C'est le shift-left appliqué à l'infrastructure.

### 1.2 Les erreurs classiques

| Domaine | Erreur | Conséquence |
|---|---|---|
| Stockage | bucket public, non chiffré, sans versioning | fuite de données, ransomware |
| Réseau | `0.0.0.0/0` sur SSH / RDP / base de données | exposition directe à Internet |
| IAM | `Action: "*"`, `Resource: "*"` | une clé volée = compte entier compromis |
| Base de données | publique, non chiffrée, mot de passe dans le code | fuite, secret dans l'état Terraform |
| Calcul | IMDSv1, disque non chiffré | vol des identifiants de l'instance (SSRF) |
| Kubernetes | `privileged`, `hostPath: /`, `hostPID`, root | évasion du conteneur vers le nœud |
| Kubernetes | pas de `limits`, pas de NetworkPolicy | déni de service, mouvement latéral |

### 1.3 Les outils

- **Checkov** : Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, GitHub Actions…
  Plus de 1 000 règles, politiques personnalisées en YAML ou Python.
- **Trivy config** (successeur de tfsec) : même binaire que pour les CVE.
- **KICS**, **Terrascan**, **OPA/Conftest** (règles en Rego) : alternatives courantes.

### 1.4 Exceptions traçables

Checkov accepte des exceptions **dans le code**, à côté de la ressource :

```hcl
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_144:Réplication inter-région non requise (données non critiques)
  bucket = "mes-logs"
}
```

Kubernetes : annotation `checkov.io/skip1: CKV_K8S_35=<justification>`.
Une exception **sans justification** doit être refusée en revue de code.

## 2. Lab

### 2.1 Premier scan

```bash
make iac
```

1. Combien de contrôles échouent pour Kubernetes ? Pour Terraform ?
2. Pour chaque commentaire `IAC-xx` et `K8S-xx` de [infra/](../../infra/), trouve le ou les
   identifiants Checkov correspondants.
3. Classe les 5 problèmes Terraform que tu corrigerais **en premier**. Justifie.

### 2.2 Second avis

```bash
docker run --rm -v "$PWD:/src" -w /src -v trivy-cache:/root/.cache \
  aquasec/trivy:0.67.2 config --severity HIGH,CRITICAL infra
```

❓ Trivy et Checkov trouvent-ils les mêmes problèmes ? Lequel est le plus « bavard » ?
Lequel préférerais-tu comme *gate* bloquante, et pourquoi ?

### 2.3 Policy as code : ta propre règle

Ton entreprise exige que toute ressource ait un tag `owner` (pour savoir qui contacter en
cas d'incident). Écris `rules/checkov/require_owner_tag.yaml`, une politique YAML qui
vérifie ce tag sur `aws_s3_bucket`, `aws_instance`, `aws_db_instance` et
`aws_security_group`. Relance `make iac` : ta règle doit apparaître et échouer 4 fois.

### 2.4 Corriger l'infrastructure

Sur ta branche de correction :

1. **Kubernetes** — réécris [infra/k8s/deployment.yaml](../../infra/k8s/deployment.yaml) :
   namespace dédié avec Pod Security Admission `restricted`, non-root, `readOnlyRootFilesystem`,
   `capabilities: drop: [ALL]`, seccomp `RuntimeDefault`, `limits`/`requests`, probes,
   image par digest, secret via `secretKeyRef`, `NetworkPolicy`, service `ClusterIP`.
2. **Terraform** — réécris [infra/terraform/main.tf](../../infra/terraform/main.tf) :
   bucket privé chiffré KMS et versionné, SG restreint avec descriptions, RDS privée et
   chiffrée avec mot de passe géré par AWS (`manage_master_user_password`), IAM au moindre
   privilège, EC2 en IMDSv2 avec disque chiffré.
3. Objectif : `make iac STRICT=1` passe, avec **au maximum 3 exceptions**, toutes justifiées.

## 3. Corrigés

<details>
<summary>2.1 — Priorités Terraform</summary>

Un ordre défendable, du plus exploitable au moins exploitable :

1. `CKV_AWS_24` — SSH ouvert à Internet (et la base sur 5432) : attaquable immédiatement.
2. `CKV_AWS_17` — RDS publique + `CKV_AWS_16` non chiffrée.
3. `CKV_AWS_286/289/290` — IAM `*:*` : transforme n'importe quelle fuite en compromission totale.
4. `CKV_AWS_20` — bucket S3 `public-read`.
5. `CKV_AWS_79` — IMDSv1 : un SSRF dans l'app permet de voler les identifiants de l'instance.

Les contrôles de « confort » (Multi-AZ, Performance Insights, monitoring) viennent après.
</details>

<details>
<summary>2.2 — Checkov vs Trivy</summary>

Sur l'infra vulnérable, Trivy remonte 19 problèmes HIGH/CRITICAL, Checkov 59 contrôles en
échec (toutes sévérités confondues, Checkov n'en affiche pas par défaut sans compte
Prisma). Les problèmes graves sont communs aux deux. Checkov est plus exhaustif, Trivy plus
sélectif : un bon compromis est Trivy (ou Checkov filtré) en *gate* bloquante, et le rapport
complet en information dans l'onglet *Code scanning*.
</details>

<details>
<summary>2.3 — Politique « tag owner »</summary>

```yaml
metadata:
  id: "CKV2_LAB_1"
  name: "Toute ressource taggable doit avoir un tag owner"
  category: "GENERAL_SECURITY"
definition:
  and:
    - cond_type: attribute
      resource_types:
        - aws_s3_bucket
        - aws_instance
        - aws_db_instance
        - aws_security_group
      attribute: tags.owner
      operator: exists
```

Pour la satisfaire sans répéter le tag partout : `default_tags { tags = { owner = "..." } }`
dans le bloc `provider "aws"`… mais Checkov, en analyse statique, ne le voit pas toujours.
Bonne occasion de discuter des limites de l'analyse statique.
</details>

<details>
<summary>2.4 — Infrastructure corrigée</summary>

La version complète est sur la branche `solution` :
`git diff main solution -- infra/`. Résultat : Kubernetes 89/89 (1 exception justifiée),
Terraform 62/62 (3 exceptions justifiées).

Extraits clés du manifeste Kubernetes :

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted   # sur le Namespace
---
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: vulnshop
          image: ghcr.io/<toi>/vulnshop@sha256:<digest>
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: 100m, memory: 128Mi }
            limits:   { cpu: 500m, memory: 256Mi }
```

Et côté Terraform, les trois lignes qui changent le plus le niveau de risque :

```hcl
cidr_blocks                 = [var.admin_cidr]   # au lieu de 0.0.0.0/0
publicly_accessible         = false
manage_master_user_password = true               # plus de mot de passe dans le code ni dans l'état
```
</details>

## ✅ Checklist

- [ ] Je sais citer 5 mauvaises configurations cloud et 5 Kubernetes
- [ ] Ma politique `CKV2_LAB_1` fonctionne
- [ ] Sur ma branche, `make iac STRICT=1` passe avec des exceptions justifiées

➡️ [Module 07 — Pipeline CI/CD](../07-ci-cd/README.md)
