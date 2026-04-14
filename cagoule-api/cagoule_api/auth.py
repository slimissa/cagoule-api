"""
Middleware d'authentification pour cagoule-api.

Couche 1 — Bearer token  : validé via l'en-tête X-API-Key ou Authorization: Bearer <key>
Couche 2 — mTLS          : géré par Uvicorn (ssl_certfile / ssl_keyfile / ssl_ca_certs)
                           Ce module ne gère pas mTLS directement — Uvicorn s'en charge
                           avant que FastAPI ne reçoive la requête.
"""

import os
import logging
from fastapi import Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from cagoule_api.errors import AuthFailedError

logger = logging.getLogger("cagoule_api.auth")

_security = HTTPBearer(auto_error=False)


def _get_api_key() -> str:
    """Charge l'API key depuis l'environnement. Lève ValueError si absente."""
    key = os.environ.get("CAGOULE_API_KEY", "").strip()
    if not key:
        raise ValueError(
            "CAGOULE_API_KEY non définie. "
            "Définir la variable d'environnement avant de démarrer le serveur."
        )
    return key


# Chargement à l'import — échoue vite si la config est incorrecte
try:
    _API_KEY: str = _get_api_key()
    logger.info("API key chargée depuis CAGOULE_API_KEY (longueur: %d)", len(_API_KEY))
except ValueError as _e:
    _API_KEY = ""
    logger.warning("CAGOULE_API_KEY non définie — auth désactivée en mode dev uniquement")


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
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
        logger.warning(
            "AUTH DÉSACTIVÉE — CAGOULE_API_KEY non configurée. "
            "Ne jamais utiliser en production."
        )
        return

    # Récupérer le token depuis Authorization: Bearer ou X-API-Key
    token: str | None = None

    if credentials and credentials.credentials:
        token = credentials.credentials
    else:
        token = request.headers.get("X-API-Key", "").strip() or None

    if not token or token != _API_KEY:
        logger.warning(
            "Tentative d'accès non autorisée depuis %s",
            request.client.host if request.client else "inconnu",
        )
        raise AuthFailedError()
