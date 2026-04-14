# cagoule-api

> ⚠️ **AVERTISSEMENT — Usage interne / Académique uniquement.**
> Ce projet est développé dans un cadre académique et de recherche (QuantOS).
> Il ne doit pas être exposé sur un réseau public sans durcissement supplémentaire.
> Aucune garantie de sécurité pour un usage en production.

API REST locale exposant les primitives cryptographiques de **CAGOULE**
(ChaCha20-Poly1305 + Argon2id) pour tests d'interopérabilité multi-langages.

**Auteur :** Slim Issa — QuantOS Project — 2026
**Version :** `0.1.0-dev`
**Stack :** Python 3.11+ | FastAPI | Pydantic v2 | Uvicorn

---

## Quickstart

### Prérequis
```bash
pip install cagoule>=1.5.0 fastapi uvicorn[standard] pydantic>=2.6 python-multipart
```

### Démarrage
```bash
# Générer une API key sécurisée
export CAGOULE_API_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Démarrer le serveur
python -m cagoule_api.server
# ou
cagoule-api
```

Le serveur démarre sur `http://127.0.0.1:8000` par défaut.

---

## Endpoints

| Méthode | Endpoint | Auth | Description |
|---------|----------|------|-------------|
| GET | `/v1/health` | Non | Statut serveur |
| POST | `/v1/encrypt` | Bearer | Chiffrer texte UTF-8 |
| POST | `/v1/decrypt` | Bearer | Déchiffrer texte |
| POST | `/v1/encrypt/file` | Bearer | Chiffrer fichier binaire |
| POST | `/v1/decrypt/file` | Bearer | Déchiffrer fichier |
| GET | `/docs` | Non | Interface Swagger UI |

---

## Authentification

### Bearer token (défaut)

```bash
# Via Authorization: Bearer
curl -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"plaintext": "Hello", "password": "secret"}' \
     http://localhost:8000/v1/encrypt

# Via X-API-Key
curl -H "X-API-Key: $CAGOULE_API_KEY" \
     -d '{"plaintext": "Hello", "password": "secret"}' \
     -H "Content-Type: application/json" \
     http://localhost:8000/v1/encrypt
```

### mTLS (optionnel)

```bash
# Générer les certificats
bash scripts/gen_certs.sh

# Démarrer avec mTLS
CAGOULE_MTLS=1 CAGOULE_API_KEY=<key> cagoule-api

# Appel avec certificat client
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
# Chiffrement
CT=$(curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"plaintext": "Message secret", "password": "mon_mot_de_passe"}' \
     http://localhost:8000/v1/encrypt | python -c "import sys,json; print(json.load(sys.stdin)['ciphertext_b64'])")

# Déchiffrement
curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{\"ciphertext_b64\": \"$CT\", \"password\": \"mon_mot_de_passe\"}" \
     http://localhost:8000/v1/decrypt
```

### Fichier binaire
```bash
# Chiffrement fichier
curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -F "file=@document.pdf" \
     -F "password=mon_mot_de_passe" \
     http://localhost:8000/v1/encrypt/file

# Déchiffrement fichier
curl -s -H "Authorization: Bearer $CAGOULE_API_KEY" \
     -F "file=@document.pdf.enc" \
     -F "password=mon_mot_de_passe" \
     http://localhost:8000/v1/decrypt/file \
     --output document_recovered.pdf
```

---

## Codes d'erreur

| Code HTTP | Code JSON | Scénario |
|-----------|-----------|----------|
| 200 | — | Succès |
| 400 | `INVALID_REQUEST` | JSON invalide / champ manquant |
| 401 | `AUTH_FAILED` | API key absente ou invalide |
| 413 | `FILE_TOO_LARGE` | Fichier > 10 MB (défaut) |
| 422 | `DECRYPTION_FAILED` | Tag AEAD invalide / mauvais mot de passe |
| 500 | `INTERNAL_ERROR` | Erreur CAGOULE inattendue |
| 503 | `SERVICE_NOT_READY` | CAGOULE non importable |

---

## Tests

```bash
pip install httpx pytest pytest-asyncio
CAGOULE_API_KEY=test_key pytest tests/ -v
```

---

## Docker

```bash
# Build
docker build -t cagoule-api .

# Run
docker run -p 8000:8000 -e CAGOULE_API_KEY=<secret> cagoule-api

# Démo interop multi-langages
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
| `FILE_SIZE_LIMIT_MB` | `10` | Limite taille fichier (MB) |

---

*cagoule-api — Slim Issa — QuantOS Project — 2026*
