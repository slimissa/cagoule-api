FROM python:3.11-slim

LABEL maintainer="Slim Issa <slim@quantos.dev>"
LABEL description="cagoule-api — Usage interne/académique uniquement"
LABEL version="1.0.0-dev"

# Avertissement au build
RUN echo "⚠️  cagoule-api — USAGE ACADEMIQUE UNIQUEMENT — Ne pas déployer en production"

WORKDIR /app

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copier pyproject.toml d'abord
COPY pyproject.toml ./

# Installer setuptools d'abord (requis pour pyproject.toml)
RUN pip install --no-cache-dir setuptools wheel

# Installer les dépendances sans mode editable
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pydantic \
    python-multipart

# Installer les dépendances de dev (optionnel)
RUN pip install --no-cache-dir pytest pytest-asyncio httpx || true

# Copier le code source
COPY cagoule_api/ ./cagoule_api/
COPY server.py .

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

CMD ["python", "server.py"]