# =============================================================================
#  DevSecOps Lab — toutes les commandes passent par Docker :
#  rien à installer à part Docker, et les MÊMES commandes tournent en local et
#  dans la CI (.github/workflows/devsecops.yml).
#
#  Par défaut, un scan qui trouve des failles N'ÉCHOUE PAS (mode apprentissage).
#  Avec STRICT=1, chaque scan devient une "security gate" bloquante :
#     make sast STRICT=1
# =============================================================================

SHELL := /bin/bash

# --- Versions figées des outils (module 09 : pourquoi figer ?) ---------------
GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks:v8.28.0
SEMGREP_IMAGE  ?= semgrep/semgrep:1.176.1
TRIVY_IMAGE    ?= aquasec/trivy:0.67.2
HADOLINT_IMAGE ?= hadolint/hadolint:v2.15.1-alpine
CHECKOV_IMAGE  ?= bridgecrew/checkov:3.3.19
SYFT_IMAGE     ?= anchore/syft:v1.52.0
GRYPE_IMAGE    ?= anchore/grype:v0.119.0
ZAP_IMAGE      ?= ghcr.io/zaproxy/zaproxy:2.17.0
ZIZMOR_IMAGE   ?= ghcr.io/zizmorcore/zizmor:1.30.1
ZAP_MAX_MINUTES ?= 6
BANDIT_VERSION ?= 1.8.6

# --- Application cible -------------------------------------------------------
APP_DIR        ?= app
APP_IMAGE      ?= vulnshop:dev
APP_CONTAINER  ?= vulnshop
APP_PORT       ?= 5000
NETWORK        ?= devsecops-lab

REPORTS        := reports
PWD            := $(shell pwd)
DOCKER_RUN     := docker run --rm -v "$(PWD):/src" -w /src

# Seuil de sévérité pour Trivy (module 04/05)
SEVERITY       ?= HIGH,CRITICAL

# Secrets injectés au lancement (module 02) — générés à chaque `make run`
SECRET_KEY     ?= $(shell openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | cut -c1-64)

ifeq ($(STRICT),1)
  ON_FAIL := exit 1
else
  ON_FAIL := echo "⚠️  Des problèmes ont été trouvés (mode apprentissage : on continue). Relance avec STRICT=1 pour bloquer."
endif

.DEFAULT_GOAL := help
.PHONY: help reports build run stop logs secrets sast bandit sast-custom sca sbom sbom-scan lint-docker image-scan iac ci-audit dast dast-full scan-all clean

help: ## Affiche cette aide
	@echo "DevSecOps Lab — cibles disponibles :"
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Option : STRICT=1 transforme les scans en gates bloquantes."

reports:
	@mkdir -p $(REPORTS) && chmod 777 $(REPORTS)

# ----------------------------------------------------------------------------
#  Application
# ----------------------------------------------------------------------------
build: ## Construit l'image Docker de l'application VulnShop
	docker build -t $(APP_IMAGE) $(APP_DIR)

run: build ## Lance VulnShop sur http://localhost:5000 (réseau Docker isolé)
	@docker network inspect $(NETWORK) >/dev/null 2>&1 || docker network create $(NETWORK) >/dev/null
	@docker rm -f $(APP_CONTAINER) >/dev/null 2>&1 || true
	@# SECRET_KEY passé par l'environnement du processus, jamais écrit dans les logs
	@SECRET_KEY=$(SECRET_KEY) docker run -d --name $(APP_CONTAINER) --network $(NETWORK) \
		-p 127.0.0.1:$(APP_PORT):5000 -e SECRET_KEY $(APP_IMAGE) >/dev/null
	@echo "Attente du démarrage..."; \
	for i in $$(seq 1 30); do curl -sf http://127.0.0.1:$(APP_PORT)/ >/dev/null && break; sleep 1; done
	@echo "✅ VulnShop écoute sur http://127.0.0.1:$(APP_PORT)"

stop: ## Arrête VulnShop
	-docker rm -f $(APP_CONTAINER)
	-docker network rm $(NETWORK)

logs: ## Affiche les logs de VulnShop
	docker logs -f $(APP_CONTAINER)

# ----------------------------------------------------------------------------
#  Scans de sécurité
# ----------------------------------------------------------------------------
secrets: reports ## [Module 02] Recherche de secrets dans tout l'historique git (Gitleaks)
	$(DOCKER_RUN) $(GITLEAKS_IMAGE) git /src --redact --verbose \
		--report-format sarif --report-path /src/$(REPORTS)/gitleaks.sarif \
		|| $(ON_FAIL)

sast: reports ## [Module 03] Analyse statique du code (Semgrep)
	$(DOCKER_RUN) $(SEMGREP_IMAGE) semgrep scan \
		--config p/python --config p/flask --config p/secrets \
		--metrics=off --error \
		--sarif-output=$(REPORTS)/semgrep.sarif \
		$(APP_DIR) \
		|| $(ON_FAIL)

bandit: reports ## [Module 03] Second avis SAST, spécialisé Python (Bandit)
	$(DOCKER_RUN) python:3.12-slim sh -c "pip install -q --disable-pip-version-check --root-user-action=ignore bandit==$(BANDIT_VERSION) && \
		bandit -r $(APP_DIR) -f txt" \
		|| $(ON_FAIL)

sast-custom: reports ## [Module 03] Lance uniquement tes règles Semgrep maison (rules/semgrep/)
	$(DOCKER_RUN) $(SEMGREP_IMAGE) semgrep scan --config rules/semgrep --metrics=off --error $(APP_DIR) \
		|| $(ON_FAIL)

sca: reports ## [Module 04] Vulnérabilités des dépendances (Trivy filesystem)
	$(DOCKER_RUN) -v trivy-cache:/root/.cache $(TRIVY_IMAGE) fs \
		--scanners vuln --severity $(SEVERITY) --exit-code 1 \
		$(APP_DIR) \
		|| $(ON_FAIL)
	@$(DOCKER_RUN) -v trivy-cache:/root/.cache $(TRIVY_IMAGE) fs -q \
		--scanners vuln --format sarif --output $(REPORTS)/trivy-fs.sarif $(APP_DIR)

sbom: reports build ## [Module 04] Génère le SBOM CycloneDX de l'image (Syft)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(PWD)/$(REPORTS):/out" \
		$(SYFT_IMAGE) $(APP_IMAGE) -o cyclonedx-json=/out/sbom.cdx.json -o table
	@echo "📦 SBOM écrit dans $(REPORTS)/sbom.cdx.json"

sbom-scan: ## [Module 04] Scanne le SBOM (Grype) — affiche EPSS et KEV pour prioriser
	@test -f $(REPORTS)/sbom.cdx.json || { echo "❌ Génère d'abord le SBOM : make sbom"; exit 1; }
	docker run --rm -v "$(PWD)/$(REPORTS):/out" $(GRYPE_IMAGE) sbom:/out/sbom.cdx.json \
		--only-fixed --sort-by risk --fail-on high \
		|| $(ON_FAIL)

lint-docker: reports ## [Module 05] Bonnes pratiques du Dockerfile (Hadolint)
	docker run --rm -i $(HADOLINT_IMAGE) hadolint - < $(APP_DIR)/Dockerfile \
		|| $(ON_FAIL)

image-scan: reports build ## [Module 05] Vulnérabilités de l'image construite (Trivy image)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache \
		-v "$(PWD):/src" -w /src $(TRIVY_IMAGE) image \
		--severity $(SEVERITY) --exit-code 1 --ignore-unfixed \
		$(APP_IMAGE) \
		|| $(ON_FAIL)

iac: reports ## [Module 06] Mauvaises configurations Terraform & Kubernetes (Checkov)
	$(DOCKER_RUN) $(CHECKOV_IMAGE) -d infra --external-checks-dir rules/checkov --compact --quiet \
		--output cli --output sarif --output-file-path console,$(REPORTS)/checkov.sarif \
		|| $(ON_FAIL)

dast: reports ## [Module 08] Scan dynamique de l'app en cours d'exécution (OWASP ZAP baseline)
	@docker inspect $(APP_CONTAINER) >/dev/null 2>&1 || { echo "❌ Lance d'abord l'app : make run"; exit 1; }
	docker run --rm --network $(NETWORK) -v "$(PWD)/$(REPORTS):/zap/wrk:rw" $(ZAP_IMAGE) \
		zap-baseline.py -t http://$(APP_CONTAINER):5000 -r zap-report.html -J zap-report.json -I \
		|| $(ON_FAIL)
	@echo "🌐 Rapport ZAP : $(REPORTS)/zap-report.html"

dast-full: reports ## [Module 08] Scan ZAP ACTIF (attaque réellement l'app — uniquement sur TA cible locale)
	@docker inspect $(APP_CONTAINER) >/dev/null 2>&1 || { echo "❌ Lance d'abord l'app : make run"; exit 1; }
	docker run --rm --network $(NETWORK) -v "$(PWD)/$(REPORTS):/zap/wrk:rw" $(ZAP_IMAGE) \
		zap-full-scan.py -t http://$(APP_CONTAINER):5000 -r zap-full-report.html -J zap-full-report.json -I -m 1 \
		-z "-config scanner.maxScanDurationInMins=$(ZAP_MAX_MINUTES) -config scanner.threadPerHost=4" \
		|| $(ON_FAIL)
	@echo "🌐 Rapport ZAP : $(REPORTS)/zap-full-report.html"

ci-audit: reports ## [Module 07/09] Audit de sécurité des workflows GitHub Actions (zizmor)
	$(DOCKER_RUN) $(ZIZMOR_IMAGE) --offline .github/workflows/ \
		|| $(ON_FAIL)

scan-all: secrets sast bandit sca lint-docker image-scan iac ci-audit ## Lance tous les scans statiques
	@echo "✅ Tous les scans sont terminés. Rapports dans $(REPORTS)/"

clean: stop ## Supprime les rapports et l'image de l'app
	rm -rf $(REPORTS)/*
	-docker rmi $(APP_IMAGE)
