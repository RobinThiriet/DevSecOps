# Module 10 — Kubernetes : admission et sécurité à l'exécution

> ⏱️ 3 h · 🎯 Empêcher un workload dangereux d'être déployé, et détecter ce qui se passe une fois déployé

## Objectifs

- Monter un cluster local avec **kind**
- Appliquer les **Pod Security Standards** avec Pod Security Admission
- Écrire une politique d'admission avec **Kyverno**
- Auditer le cluster avec **kube-bench** (benchmark CIS)
- Comprendre la détection à l'exécution (**Falco**)

## 1. Cours

### 1.1 Trois lignes de défense

```
 CI (modules 03-09)          Admission (ce module)          Exécution (ce module)
 "le manifeste est-il     →  "le cluster accepte-t-il   →   "le comportement du
  correct ?"                  ce pod ?"                      conteneur est-il normal ?"
  Checkov, Trivy              Pod Security Admission,         Falco, Tetragon,
                              Kyverno, OPA Gatekeeper         audit logs
```

La CI peut être contournée (un `kubectl apply` à la main, un pipeline mal configuré).
**L'admission est le dernier contrôle avant l'exécution** : elle s'applique à tout le monde.

### 1.2 Pod Security Standards

Trois profils officiels, appliqués par namespace via une simple étiquette :

| Profil | Pour qui | Interdit notamment |
|---|---|---|
| `privileged` | composants système | rien |
| `baseline` | la plupart des apps | `privileged`, `hostNetwork`, `hostPID`, `hostPath`, capabilities dangereuses |
| `restricted` | apps durcies (**cible**) | tout ce qui précède + root, élévation de privilèges ; exige `drop: [ALL]` et seccomp |

```yaml
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted   # refuse
    pod-security.kubernetes.io/warn: restricted      # avertit seulement
    pod-security.kubernetes.io/audit: restricted     # journalise seulement
```

### 1.3 Au-delà : les moteurs de politiques

PSA ne couvre que la sécurité des pods. Pour « pas de tag `latest` », « images signées
uniquement », « tag `owner` obligatoire », on utilise un moteur de politiques :
**Kyverno** (politiques en YAML + expressions CEL) ou **OPA Gatekeeper** (langage Rego).

### 1.4 Détection à l'exécution

Même avec tout ce qui précède, une faille applicative (l'injection de commande de VulnShop)
permet d'exécuter du code **dans** le conteneur. **Falco** observe les appels système du
noyau et alerte sur les comportements suspects : un shell lancé dans un conteneur, la
lecture de `/etc/shadow`, une connexion sortante inattendue…

## 2. Lab

### 2.0 Installer kind et kubectl

```bash
# kind — https://kind.sigs.k8s.io/docs/user/quick-start/#installation
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64
# kubectl — https://kubernetes.io/docs/tasks/tools/
curl -LO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kind kubectl && sudo mv kind kubectl /usr/local/bin/

kind create cluster --name devsecops-lab
kubectl get nodes
```

Charge les images de VulnShop dans le cluster (pas de registre nécessaire) :

```bash
make build                                            # image vulnérable : vulnshop:dev
kind load docker-image vulnshop:dev --name devsecops-lab
```

### 2.1 Pod Security Admission

```bash
kubectl create namespace psa-lab
kubectl label namespace psa-lab pod-security.kubernetes.io/enforce=restricted

sed 's/namespace: default/namespace: psa-lab/; s#image: vulnshop:latest#image: vulnshop:dev#' \
  infra/k8s/deployment.yaml | kubectl apply -n psa-lab -f -

kubectl -n psa-lab get deploy,rs,pods
kubectl -n psa-lab get events --field-selector reason=FailedCreate
```

1. Le `Deployment` est-il créé ? Et les pods ? Explique la différence.
2. Liste toutes les violations signalées et fais le lien avec les contrôles Checkov du
   module 06.
3. Passe le namespace en `baseline` : quelles violations disparaissent ?

### 2.2 Déployer la version durcie

Avec ton manifeste corrigé du module 06 et ton image corrigée du module 05 :

```bash
docker build -t vulnshop:fixed app/                   # sur ta branche de correction
kind load docker-image vulnshop:fixed --name devsecops-lab
# dans le manifeste : image: vulnshop:fixed  et  imagePullPolicy: IfNotPresent
kubectl apply -f infra/k8s/deployment.yaml
kubectl -n vulnshop create secret generic vulnshop --from-literal=secret-key="$(openssl rand -hex 32)"
kubectl -n vulnshop rollout status deploy/vulnshop
```

Vérifie que l'app répond **depuis le cluster**, et que la `NetworkPolicy` empêche le pod
de sortir sur Internet :

```bash
kubectl -n vulnshop exec deploy/vulnshop -- \
  python -c "import urllib.request; urllib.request.urlopen('http://example.com', timeout=5)"
```

❓ Pourquoi bloquer les connexions **sortantes** limite-t-il l'impact de l'injection de
commande, même si elle n'était pas corrigée ?

### 2.3 Kyverno : interdire le tag `latest`

```bash
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.19.1/install.yaml
kubectl -n kyverno rollout status deploy/kyverno-admission-controller
```

Écris une `ValidatingPolicy` (API `policies.kyverno.io/v1`) qui refuse tout pod dont une
image n'a **pas de tag**, ou a le tag `latest`, sauf si elle est référencée par digest.
Teste-la sans rien créer grâce à `--dry-run=server` :

```bash
for img in nginx:latest nginx nginx:1.29 localhost:5000/app \
           nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000; do
  echo "== $img"; kubectl run t --image="$img" --dry-run=server 2>&1 | tail -1
done
```

Attendu : refus pour `nginx:latest`, `nginx` et `localhost:5000/app`, acceptation pour
les deux autres. ⚠️ Le piège : `localhost:5000/app` contient un `:`… qui n'est pas un tag.

Pour aller plus loin : une `ImageValidatingPolicy` peut exiger une signature cosign
(module 09) pour toute image déployée.

### 2.4 kube-bench : auditer le cluster

```bash
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/v0.16.0/job.yaml
kubectl wait --for=condition=complete job/kube-bench --timeout=180s
kubectl logs job/kube-bench | less
```

1. Combien de contrôles `FAIL` sur le plan de contrôle ?
2. Choisis-en trois, explique le risque et la remédiation proposée.
3. Pourquoi certains sont-ils acceptables sur un cluster de lab kind, mais pas en production ?

### 2.5 Falco (optionnel)

> ⚠️ Falco a besoin d'accéder aux appels système du noyau. **Sous WSL2, nos tests
> montrent qu'il démarre mais ne remonte aucune alerte** (les points de trace nécessaires ne
> sont pas exposés). Utilise une VM Linux native ou un cluster cloud pour cet exercice.

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf --set tty=true
```

Puis, dans un autre terminal, ouvre un shell dans un pod VulnShop
(`kubectl -n vulnshop exec -it deploy/vulnshop -- sh`) et regarde les logs de Falco
(`kubectl -n falco logs -l app.kubernetes.io/name=falco -f`).
❓ Pourquoi un shell interactif dans un conteneur de production est-il suspect ?
Comment une image *distroless* (module 05) rendrait-elle cette attaque plus difficile ?

### 2.6 Nettoyage

```bash
kind delete cluster --name devsecops-lab
```

## 3. Corrigés

<details>
<summary>2.1 — PSA</summary>

Le `Deployment` et le `ReplicaSet` sont créés : PSA ne contrôle que les **pods**. Le
`ReplicaSet` essaie en boucle de créer ses pods, qui sont refusés (`FailedCreate`). Au
moment du `kubectl apply`, un **avertissement** liste déjà les violations : `hostNetwork`,
`hostPID`, `hostPort`, `privileged`, `allowPrivilegeEscalation`, capabilities non retirées,
volume `hostPath`, `runAsNonRoot`, `runAsUser=0`, seccomp absent. Ce sont les mêmes que
`CKV_K8S_16/17/19/20/23/28/31/37/40`… Checkov les trouve en CI, PSA les **bloque** au
déploiement.

En `baseline`, restent refusés : `privileged`, `hostNetwork`, `hostPID`, `hostPath`,
`hostPort`. Disparaissent : root, élévation de privilèges, capabilities, seccomp.
</details>

<details>
<summary>2.2 — Pourquoi bloquer la sortie</summary>

Un attaquant qui exécute du code dans le conteneur veut presque toujours **communiquer vers
l'extérieur** : télécharger un outil, ouvrir un shell inversé, exfiltrer des données. Sans
connexion sortante, il est enfermé dans un conteneur en lecture seule, sans shell de
login, sans capabilities : l'impact est drastiquement réduit. C'est la défense en profondeur.
</details>

<details>
<summary>2.3 — ValidatingPolicy</summary>

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: disallow-latest-tag
spec:
  validationActions: [Deny]
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: [v1]
        operations: [CREATE, UPDATE]
        resources: [pods]
  validations:
    - expression: >-
        object.spec.containers.all(c,
          c.image.contains('@sha256:') ||
          (c.image.split('/')[size(c.image.split('/')) - 1].contains(':') && !c.image.endsWith(':latest')))
      message: "Chaque image doit avoir un tag explicite autre que 'latest' (ou un digest)."
```

L'astuce : chercher le `:` uniquement dans le **dernier segment** du nom (après le dernier
`/`), pour ne pas confondre le port d'un registre avec un tag. Pour être complet, il
faudrait aussi couvrir `initContainers` et `ephemeralContainers`.

(Les politiques `ClusterPolicy` de l'API `kyverno.io/v1` fonctionnent encore, mais
Kyverno 1.19 affiche un avertissement de dépréciation au profit des politiques CEL.)
</details>

<details>
<summary>2.4 — kube-bench</summary>

Sur un cluster kind par défaut : 10 `FAIL` sur le *master*, par exemple :
- `1.2.16`–`1.2.19` : pas de **journal d'audit** de l'API server → impossible de savoir qui
  a fait quoi après un incident (catégorie *Repudiation* de STRIDE, module 01).
- `1.2.15` : profilage activé → surface d'attaque et fuite d'information inutiles.
- `1.2.5` : le certificat du kubelet n'est pas vérifié → usurpation possible d'un nœud.

Acceptable sur un cluster jetable, local, sans données ; inacceptable en production. Les
offres managées (EKS, GKE, AKS) gèrent une partie de ces réglages pour toi — mais pas tous.
</details>

## ✅ Checklist

- [ ] Le manifeste vulnérable est refusé par PSA `restricted`
- [ ] Mon manifeste corrigé tourne sous PSA `restricted`, sortie bloquée
- [ ] Ma politique Kyverno refuse `latest` sans se faire piéger par un port de registre
- [ ] J'ai lu et interprété le rapport kube-bench

➡️ [Module 11 — Projet final](../11-projet-final/README.md)
