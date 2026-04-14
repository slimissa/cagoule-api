"""
Middleware d'authentification pour cagoule-api.

Couche 1 — Bearer token  : validé via l'en-tête X-API-Key ou Authorization: Bearer <key>
Couche 2 — mTLS          : géré par Uvicorn (ssl_certfile / ssl_keyfile / ssl_ca_certs)
                           Ce module ne gère pas mTLS directement — Uvicorn s'en charge
                           avant que FastAPI ne reçoive la requête.
"""

import os
import secrets
import logging
from typing import Optional
from fastapi import Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from cagoule_api.errors import AuthFailedError

logger = logging.getLogger("cagoule_api.auth")

_security = HTTPBearer(auto_error=False)


def _get_api_key() -> Optional[str]:
    """Charge l'API key depuis l'environnement. Retourne None si absente."""
    key = os.environ.get("CAGOULE_API_KEY", "").strip()
    return key if key else None


# Chargement à l'import
_API_KEY: Optional[str] = _get_api_key()

if _API_KEY:
    logger.info("API key chargée depuis CAGOULE_API_KEY (longueur: %d)", len(_API_KEY))
    if len(_API_KEY) < 32:
        logger.warning("⚠️ API key courte (%d caractères) — utiliser au moins 32 caractères", len(_API_KEY))
else:
    warning_msg = """
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  ⚠️  ATTENTION: AUTHENTIFICATION DÉSACTIVÉE  ⚠️                          ║
    ║                                                                          ║
    ║  CAGOULE_API_KEY non définie dans l'environnement.                       ║
    ║  Tout client pourra accéder aux endpoints protégés sans authentification.║
    ║                                                                          ║
    ║  À DÉFINIR IMPÉRATIVEMENT EN PRODUCTION :                                ║
    ║    export CAGOULE_API_KEY="$(openssl rand -hex 32)"                      ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    """
    print(warning_msg)
    logger.warning("AUTHENTIFICATION DÉSACTIVÉE — CAGOULE_API_KEY non définie")


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
) -> None:
    """
    Dépendance FastAPI — injecter dans tous les endpoints protégés.

    Accepte :
      - Authorization: Bearer <key>
      - X-API-Key: <key>

    Lève AuthFailedError si l'authentification échoue.
    """
    # Mode dev sans clé configurée : on avertit mais on laisse passer
    if not _API_KEY:
        return

    # Récupérer le token
    token: Optional[str] = None

    if credentials and credentials.credentials:
        token = credentials.credentials
    else:
        token = request.headers.get("X-API-Key", "").strip() or None

    # Validation en temps constant
    if not token or not secrets.compare_digest(token, _API_KEY):
        client_info = f"{request.client.host}:{request.client.port}" if request.client else "inconnu"
        logger.warning(
            "Authentification échouée depuis %s - méthode: %s",
            client_info,
            "Bearer" if credentials else "X-API-Key",
        )
        raise AuthFailedError()


def generate_api_key(length: int = 32) -> str:
    """
    Génère une API key sécurisée.
    
    Args:
        length: Longueur en bytes (par défaut 32 = 64 caractères hex)
    
    Returns:
        Clé hexadécimale aléatoire.
    """
    return secrets.token_hex(length)
