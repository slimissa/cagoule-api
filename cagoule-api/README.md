# cagoule-api

> ⚠️ **AVERTISSEMENT — Usage interne / Académique uniquement.**
> Ce projet est développé dans un cadre académique et de recherche (QuantOS).
> Il ne doit pas être exposé sur un réseau public sans durcissement supplémentaire.
> Aucune garantie de sécurité pour un usage en production.

API REST locale exposant les primitives cryptographiques de **CAGOULE**
(ChaCha20-Poly1305 + Argon2id) via FastAPI — pour tests d'interopérabilité multi-langages (Go, Rust, Node.js, C, etc.).

**Auteur :** Slim Issa — QuantOS Project — 2026
**Version :** `0.1.0-dev`
**Stack :** Python 3.11+ | FastAPI | Pydantic v2 | Uvicorn
**Auth :** Bearer token + mTLS optionnel

---

## Installation

### Prérequis

- Python 3.11+
- `cagoule >= 1.5.0` installé
- `python3-venv` (`sudo apt install python3-full python3-venv`)

### Setup avec venv (recommandé sur Ubuntu/Debian)

```bash
cd cagoule-api
python3 -m venv .venv
source .venv/bin/activate
pip install ".[dev]"
```

### Démarrage

```bash
export CAGOULE_API_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python -m cagoule_api.server
```

Interface Swagger : `http://127.0.0.1:8000/docs`

### Script de démarrage rapide

```bash
#!/usr/bin/env bash
# run.sh
source .venv/bin/activate
export CAGOULE_API_KEY="${CAGOULE_API_KEY:?Définir CAGOULE_API_KEY}"
python -m cagoule_api.server
```

---

## Endpoints `/v1/`

| Méthode | Endpoint | Auth | Description |
|---------|----------|------|-------------|
| GET | `/v1/health` | Non | Statut serveur + version |
| POST | `/v1/encrypt` | Bearer | Chiffrer du texte UTF-8 |
| POST | `/v1/decrypt` | Bearer | Déchiffrer du texte |
| POST | `/v1/encrypt/file` | Bearer | Chiffrer un fichier binaire |
| POST | `/v1/decrypt/file` | Bearer | Déchiffrer un fichier |
| GET | `/docs` | Non | Swagger UI |
| GET | `/openapi.json` | Non | Schéma OpenAPI |

---

## Authentification

### Bearer token

```bash
curl -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"plaintext": "Hello QuantOS", "password": "secret"}' \
     http://localhost:8000/v1/encrypt

# Ou via X-API-Key
curl -H "X-API-Key: $CAGOULE_API_KEY" ...
```

### mTLS (optionnel)

```bash
bash scripts/gen_certs.sh
CAGOULE_MTLS=1 CAGOULE_API_KEY=$CAGOULE_API_KEY python -m cagoule_api.server

curl --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt \
     -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -d '{"plaintext": "Hello", "password": "secret"}' \
     -H "Content-Type: application/json" \
     https://localhost:8000/v1/encrypt
```

---

## Exemples curl

### Roundtrip texte

```bash
CT=$(curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"plaintext": "Message secret QuantOS", "password": "mon_mot_de_passe"}' \
     http://localhost:8000/v1/encrypt \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['ciphertext_b64'])")

curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"ciphertext_b64\": \"$CT\", \"password\": \"mon_mot_de_passe\"}" \
     http://localhost:8000/v1/decrypt
```

### Roundtrip fichier binaire

```bash
# 1. Chiffrement → retourne {"ciphertext_b64": "..."}
curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -F "file=@document.pdf" -F "password=secret" \
     http://localhost:8000/v1/encrypt/file > encrypted.json

# 2. Déchiffrement → envoyer le JSON retourné par encrypt/file
curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -F "file=@encrypted.json" -F "password=secret" \
     http://localhost:8000/v1/decrypt/file --output document_recovered.pdf
```

> **Important :** `/v1/decrypt/file` attend le fichier JSON `{"ciphertext_b64": "..."}` produit
> par `/v1/encrypt/file`. Ne pas envoyer des bytes bruts.

---

## Codes d'erreur

| HTTP | Code JSON | Scénario |
|------|-----------|----------|
| 200 | — | Succès |
| 400 | `INVALID_REQUEST` | JSON invalide / champ manquant |
| 401 | `AUTH_FAILED` | API key absente ou invalide |
| 413 | `FILE_TOO_LARGE` | Fichier > limite (défaut 10 MB) |
| 422 | `DECRYPTION_FAILED` | Tag AEAD invalide / mauvais mot de passe |
| 500 | `INTERNAL_ERROR` | Erreur CAGOULE inattendue |
| 503 | `SERVICE_NOT_READY` | CAGOULE non importable |

Format unifié :
```json
{
  "error": {
    "code": "DECRYPTION_FAILED",
    "message": "Déchiffrement impossible",
    "details": "Tag d'authentification invalide"
  }
}
```

---

## Tests

```bash
CAGOULE_API_KEY=test_key pytest tests/ -v
```

29 tests — unitaires (`test_crypto.py`) + intégration (`test_api.py`) :
roundtrip texte/binaire, tag AEAD altéré, Base64 malformé, auth Bearer valide/invalide/absent,
limite taille fichier, ServiceNotReady (mock).

---

## Docker

```bash
docker build -t cagoule-api .
docker run -p 8000:8000 -e CAGOULE_API_KEY=<secret> cagoule-api

# Démo interop Node.js
CAGOULE_API_KEY=<secret> docker compose --profile demo up
```

---

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `CAGOULE_API_KEY` | — | **Obligatoire** — clé Bearer |
| `CAGOULE_HOST` | `127.0.0.1` | Interface d'écoute |
| `CAGOULE_PORT` | `8000` | Port TCP |
| `CAGOULE_MTLS` | `0` | Activer mTLS (`1`/`true`) |
| `FILE_SIZE_LIMIT_MB` | `10` | Limite fichier (MB) |

---

## Structure du projet

```
cagoule-api/
├── cagoule_api/
│   ├── server.py           # FastAPI app, routers, lifespan
│   ├── crypto.py           # Wrapper CAGOULE + Base64
│   ├── models.py           # Schémas Pydantic v2
│   ├── auth.py             # Bearer token (+ mTLS via Uvicorn)
│   └── errors.py           # Exception handlers HTTP
├── tests/
│   ├── test_api.py         # 29 tests intégration
│   └── test_crypto.py      # Tests unitaires crypto
├── scripts/
│   ├── gen_certs.sh        # Certificats self-signed mTLS
│   └── node_client_demo.js # Démo interop Node.js
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

---

## Décisions d'architecture

| ADR | Décision | Raison |
|-----|----------|--------|
| ADR-01 | Base64 JSON | Compatible tous langages |
| ADR-02 | Bearer + mTLS | Deux couches indépendantes |
| ADR-03 | HTTP local | Isolation réseau côté utilisateur |
| ADR-04 | `/v1/` dès v0.1 | Discipline de versioning |
| ADR-05 | 422 pour crypto | Sémantiquement correct |
| ADR-06 | Pas de PyPI | Usage académique uniquement |
| ADR-07 | Pydantic v2 | 5–50x plus rapide que v1 |

---

## Sécurité (outil dev)

- Aucun plaintext ni password loggué
- `secrets.compare_digest()` pour l'API key (protection timing attack)
- Limite taille fichier active (10 MB par défaut)
- Banner académique à chaque démarrage

---

*cagoule-api — Slim Issa — QuantOS Project — 2026*