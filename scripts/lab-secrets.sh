#!/usr/bin/env bash
# Module 02 — crée un dépôt git JETABLE contenant des secrets (factices) cachés
# dans l'historique. Les secrets sont générés aléatoirement à chaque exécution :
# ils ne correspondent à aucun vrai compte et ne sont jamais commités dans
# le dépôt de formation.
#
# Usage : ./scripts/lab-secrets.sh [dossier]   (défaut : /tmp/secret-lab)
set -euo pipefail

LAB_DIR="${1:-/tmp/secret-lab}"

rand() { (LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2") 2>/dev/null || true; }

AWS_KEY_ID="AKIA$(rand 'A-Z2-7' 16)"
AWS_SECRET="$(rand 'A-Za-z0-9' 40)"
GH_TOKEN="ghp_$(rand 'A-Za-z0-9' 36)"
DB_URL="postgres://admin:$(rand 'a-z0-9' 12)@db.internal:5432/shop"

rm -rf "$LAB_DIR"
mkdir -p "$LAB_DIR"
cd "$LAB_DIR"
git init -q -b main
git config user.name "Stagiaire"
git config user.email "stagiaire@example.com"

cat > README.md <<'EOF'
# Projet legacy
Un dépôt "propre"... en apparence.
EOF
git add . && git commit -qm "init"

# Commit 2 : un développeur pressé commite ses identifiants AWS
cat > config.py <<EOF
AWS_ACCESS_KEY_ID = "$AWS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "$AWS_SECRET"
REGION = "eu-west-3"
EOF
git add . && git commit -qm "ajout config AWS"

# Commit 3 : il "corrige" en supprimant le fichier... mais l'historique garde tout
git rm -q config.py
cat > config.py <<'EOF'
import os
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
REGION = "eu-west-3"
EOF
git add . && git commit -qm "fix: secrets via variables d'environnement"

# Commit 4 : un token GitHub dans un script de déploiement
mkdir -p deploy
cat > deploy/release.sh <<EOF
#!/bin/sh
curl -H "Authorization: token $GH_TOKEN" https://api.github.com/repos/acme/shop/releases
EOF
git add . && git commit -qm "script de release"

# Commit 5 : une URL de connexion avec mot de passe dans un .env
echo "DATABASE_URL=$DB_URL" > .env
git add . && git commit -qm "ajout .env"

echo "✅ Dépôt de lab créé dans $LAB_DIR ($(git rev-list --count HEAD) commits)"
echo "   À toi de jouer : trouve tous les secrets, y compris ceux qui ont été 'supprimés'."
