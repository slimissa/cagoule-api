#!/usr/bin/env python3
"""
cagoule-api — Serveur FastAPI principal.

⚠️  AVERTISSEMENT : Usage interne / académique uniquement.
    Ne pas exposer sur un réseau public sans mTLS et durcissement supplémentaire.
    Aucune garantie de sécurité pour un usage en production.
"""

import logging
import os
import json
import base64
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Depends, UploadFile, File, Form
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from cagoule_api.__version__ import __version__
from cagoule_api import crypto
from cagoule_api.auth import require_auth
from cagoule_api.errors import (
    AuthFailedError,
    DecryptionFailedError,
    FileTooLargeError,
    ServiceNotReadyError,
    auth_failed_handler,
    decryption_failed_handler,
    file_too_large_handler,
    http_exception_handler,
    internal_error_handler,
    service_not_ready_handler,
    validation_exception_handler,
)
from cagoule_api.models import (
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
    HealthResponse,
)

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cagoule_api.server")

# Limite taille fichier (bytes) — configurable via env FILE_SIZE_LIMIT_MB
_FILE_LIMIT_MB = int(os.environ.get("FILE_SIZE_LIMIT_MB", "10"))
_FILE_LIMIT_BYTES = _FILE_LIMIT_MB * 1024 * 1024


# ──────────────────────────────────────────────
# Banner académique
# ──────────────────────────────────────────────

_BANNER = f"""
╔══════════════════════════════════════════════════════════════════╗
║              cagoule-api  v{__version__:<10}                       ║
║                                                                  ║
║  ⚠️  USAGE INTERNE / ACADÉMIQUE UNIQUEMENT                       ║
║  Ne pas exposer sur un réseau public sans durcissement.          ║
║  Pas de garantie de sécurité pour un usage en production.        ║
║  Auteur : Slim Issa — QuantOS Project — 2026                     ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ──────────────────────────────────────────────
# Lifespan (startup / shutdown)
# ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gère le cycle de vie de l'application."""
    # Startup
    print(_BANNER)
    logger.warning("=== DÉMARRAGE cagoule-api — USAGE ACADÉMIQUE UNIQUEMENT ===")
    logger.info("Version       : %s", __version__)
    logger.info("Hôte          : %s", os.environ.get("CAGOULE_HOST", "127.0.0.1"))
    logger.info("Port          : %s", os.environ.get("CAGOULE_PORT", "8000"))
    logger.info("Limite fichier: %d MB", _FILE_LIMIT_MB)
    logger.info("mTLS          : %s", "activé" if os.environ.get("CAGOULE_MTLS") else "désactivé")

    if not crypto.is_cagoule_available():
        logger.critical("CAGOULE non disponible — les endpoints crypto seront en erreur 503")
    else:
        logger.info("CAGOULE       : disponible ✓")

    yield

    # Shutdown
    logger.info("cagoule-api arrêté proprement.")


# ──────────────────────────────────────────────
# Application FastAPI
# ──────────────────────────────────────────────

app = FastAPI(
    title="cagoule-api",
    description=(
        "⚠️ Usage interne/académique uniquement. "
        "API REST exposant les primitives cryptographiques CAGOULE "
        "(ChaCha20-Poly1305 + Argon2id) pour tests d'interopérabilité."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

# Enregistrement des exception handlers
app.add_exception_handler(AuthFailedError, auth_failed_handler)
app.add_exception_handler(DecryptionFailedError, decryption_failed_handler)
app.add_exception_handler(ServiceNotReadyError, service_not_ready_handler)
app.add_exception_handler(FileTooLargeError, file_too_large_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, internal_error_handler)


# ──────────────────────────────────────────────
# Endpoints — /v1/
# ──────────────────────────────────────────────

@app.get(
    "/v1/health",
    response_model=HealthResponse,
    summary="Vérification de santé",
    tags=["Infra"],
)
async def health() -> HealthResponse:
    """Retourne le statut du serveur et la disponibilité de CAGOULE."""
    return HealthResponse(
        status="ok",
        version=__version__,
        cagoule_available=crypto.is_cagoule_available(),
    )


@app.post(
    "/v1/encrypt",
    response_model=EncryptResponse,
    summary="Chiffrer un texte",
    tags=["Crypto — Texte"],
    dependencies=[Depends(require_auth)],
)
async def encrypt_text_endpoint(body: EncryptRequest) -> EncryptResponse:
    """
    Chiffre un texte UTF-8 avec CAGOULE (ChaCha20-Poly1305 + Argon2id).

    Retourne le ciphertext encodé en Base64.
    """
    ciphertext_b64 = crypto.encrypt_text(body.plaintext, body.password)
    return EncryptResponse(ciphertext_b64=ciphertext_b64)


@app.post(
    "/v1/decrypt",
    response_model=DecryptResponse,
    summary="Déchiffrer un texte",
    tags=["Crypto — Texte"],
    dependencies=[Depends(require_auth)],
)
async def decrypt_text_endpoint(body: DecryptRequest) -> DecryptResponse:
    """
    Déchiffre un ciphertext Base64 produit par /v1/encrypt.

    Retourne le plaintext UTF-8.
    - 422 si le tag AEAD est invalide ou le mot de passe incorrect.
    """
    plaintext = crypto.decrypt_text(body.ciphertext_b64, body.password)
    return DecryptResponse(plaintext=plaintext)


@app.post(
    "/v1/encrypt/file",
    summary="Chiffrer un fichier",
    tags=["Crypto — Fichiers"],
    dependencies=[Depends(require_auth)],
)
async def encrypt_file_endpoint(
    file: UploadFile = File(..., description="Fichier à chiffrer"),
    password: str = Form(..., description="Mot de passe Argon2id"),
) -> EncryptResponse:
    """
    Chiffre un fichier binaire arbitraire avec CAGOULE.

    Limite par défaut : 10 MB (configurable via FILE_SIZE_LIMIT_MB).
    Retourne le ciphertext encodé en Base64 JSON.
    """
    data = await file.read()
    if len(data) > _FILE_LIMIT_BYTES:
        raise FileTooLargeError(
            f"Fichier trop volumineux : {len(data)} octets > limite {_FILE_LIMIT_BYTES} octets "
            f"({_FILE_LIMIT_MB} MB)"
        )
    logger.debug("encrypt_file: %s (%d octets)", file.filename, len(data))
    ciphertext_b64 = crypto.encrypt_bytes(data, password)
    return EncryptResponse(ciphertext_b64=ciphertext_b64)


@app.post(
    "/v1/decrypt/file",
    summary="Déchiffrer un fichier",
    tags=["Crypto — Fichiers"],
    dependencies=[Depends(require_auth)],
)
async def decrypt_file_endpoint(
    file: UploadFile = File(..., description="Fichier chiffré au format JSON (ciphertext_b64)"),
    password: str = Form(..., description="Mot de passe Argon2id"),
) -> Response:
    """
    Déchiffre un fichier chiffré par /v1/encrypt/file.

    Le fichier doit être au format JSON: {"ciphertext_b64": "..."}
    Retourne le fichier déchiffré en octet-stream.
    - 422 si le tag AEAD est invalide ou le mot de passe incorrect.
    """
    # Lire le contenu du fichier
    content = await file.read()
    
    if len(content) > _FILE_LIMIT_BYTES:
        raise FileTooLargeError(
            f"Fichier trop volumineux : {len(content)} octets > limite {_FILE_LIMIT_BYTES} octets"
        )
    
    # Extraire le ciphertext du JSON
    try:
        # Essayer de décoder le contenu comme JSON
        content_str = content.decode('utf-8')
        data = json.loads(content_str)
        ciphertext_b64 = data.get("ciphertext_b64")
        
        if not ciphertext_b64:
            raise DecryptionFailedError("JSON invalide: champ 'ciphertext_b64' manquant")
        
        # Vérifier que c'est du base64 valide
        base64.b64decode(ciphertext_b64, validate=True)
        
    except UnicodeDecodeError as e:
        raise DecryptionFailedError(f"Le fichier n'est pas un JSON valide (erreur UTF-8): {e}")
    except json.JSONDecodeError as e:
        raise DecryptionFailedError(f"Le fichier n'est pas un JSON valide: {e}")
    except Exception as e:
        raise DecryptionFailedError(f"Erreur lors de la lecture du fichier: {e}")
    
    logger.debug("decrypt_file: ciphertext_b64 trouvé, longueur: %d", len(ciphertext_b64))
    
    # Déchiffrer
    try:
        plaintext_bytes = crypto.decrypt_bytes(ciphertext_b64, password)
    except DecryptionFailedError:
        raise
    except Exception as e:
        logger.error("Erreur inattendue lors du déchiffrement: %s", e)
        raise DecryptionFailedError(f"Erreur lors du déchiffrement: {e}")
    
    # Déterminer le nom du fichier de sortie
    original_filename = file.filename or "decrypted_file"
    # Enlever l'extension .json si présente
    if original_filename.lower().endswith('.json'):
        original_filename = original_filename[:-5]
    if original_filename.endswith('.enc'):
        original_filename = original_filename[:-4]
    
    output_filename = f"{original_filename}.dec"
    
    return Response(
        content=plaintext_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{output_filename}"'},
    )


# ──────────────────────────────────────────────
# Point d'entrée CLI
# ──────────────────────────────────────────────

def main():
    """Point d'entrée principal pour la ligne de commande."""
    host = os.environ.get("CAGOULE_HOST", "127.0.0.1")
    port = int(os.environ.get("CAGOULE_PORT", "8000"))
    use_mtls = os.environ.get("CAGOULE_MTLS", "").lower() in ("1", "true", "yes")

    ssl_kwargs = {}
    if use_mtls:
        ssl_kwargs = {
            "ssl_keyfile": os.environ.get("CAGOULE_SSL_KEY", "certs/server.key"),
            "ssl_certfile": os.environ.get("CAGOULE_SSL_CERT", "certs/server.crt"),
            "ssl_ca_certs": os.environ.get("CAGOULE_SSL_CA", "certs/ca.crt"),
        }
        logger.info("mTLS activé avec certificats depuis certs/")

    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        reload=True,
        log_level="info",
        **ssl_kwargs,
    )


if __name__ == "__main__":
    main()