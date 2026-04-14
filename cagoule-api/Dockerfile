FROM python:3.11-slim

LABEL maintainer="Slim Issa <slim@quantos.dev>"
LABEL description="cagoule-api — Usage interne/académique uniquement"
LABEL version="0.1.0-dev"

# Avertissement au build
RUN echo "⚠️  cagoule-api — USAGE ACADEMIQUE UNIQUEMENT — Ne pas déployer en production"

WORKDIR /app

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copie et installation des dépendances
COPY pyproject.toml ./
RUN pip install --no-cache-dir ".[dev]"

# Code source
COPY cagoule_api/ ./cagoule_api/
COPY tests/ ./tests/

# Utilisateur non-root
RUN useradd --no-create-home --shell /bin/false cagoule
USER cagoule

EXPOSE 8000

# Variables d'environnement par défaut (à surcharger)
ENV CAGOULE_HOST=0.0.0.0
ENV CAGOULE_PORT=8000
ENV FILE_SIZE_LIMIT_MB=10

# L'API key DOIT être fournie au runtime — jamais en dur dans l'image
# docker run -e CAGOULE_API_KEY=<secret> ...

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/health')"

CMD ["python", "-m", "cagoule_api.server"]
