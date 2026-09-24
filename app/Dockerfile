# VULN-10 : Dockerfile volontairement mal écrit (module 05 - Conteneurs)
# - image de base obsolète et lourde (Python 3.7, EOL, des centaines de CVE)
# - tag non figé, pas de digest
# - secret passé en variable d'environnement
# - ADD au lieu de COPY, pas de .dockerignore
# - paquets inutiles, cache apt non nettoyé
# - exécution en root, pas de HEALTHCHECK
FROM python:3.7

ENV DB_PASSWORD=admin123

RUN apt-get update && apt-get install -y curl wget vim netcat-traditional iputils-ping

ADD . /app
WORKDIR /app

RUN pip install -r requirements.txt

EXPOSE 5000
CMD python app.py
