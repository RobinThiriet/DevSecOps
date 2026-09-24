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
