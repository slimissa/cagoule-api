"""
Handlers d'exceptions HTTP pour cagoule-api.
Chaque erreur métier retourne un JSON structuré conforme à l'ADR-05.
"""

import logging
from fastapi import Request
from starlette import status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("cagoule_api.errors")


# ──────────────────────────────────────────────
# Exceptions métier personnalisées
# ──────────────────────────────────────────────

class AuthFailedError(Exception):
    """API key absente ou invalide."""


class DecryptionFailedError(Exception):
    """Tag AEAD invalide ou mot de passe incorrect."""

    def __init__(self, details: str = "Invalid authentication tag"):
        self.details = details
        super().__init__(details)


class ServiceNotReadyError(Exception):
    """CAGOULE non importable au démarrage."""


class FileTooLargeError(Exception):
    """Fichier dépasse la limite configurée."""


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _error_body(code: str, message: str, details: str | None = None) -> dict:
    payload = {"code": code, "message": message}
    if details:
        payload["details"] = details
    return {"error": payload}


# ──────────────────────────────────────────────
# Handlers à enregistrer sur l'app FastAPI
# ──────────────────────────────────────────────

async def auth_failed_handler(request: Request, exc: AuthFailedError):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=_error_body("AUTH_FAILED", "API key absente ou invalide"),
        headers={"WWW-Authenticate": "Bearer"},
    )


async def decryption_failed_handler(request: Request, exc: DecryptionFailedError):
    return JSONResponse(
        status_code=422,
        content=_error_body(
            "DECRYPTION_FAILED",
            "Déchiffrement impossible",
            exc.details,
        ),
    )


async def service_not_ready_handler(request: Request, exc: ServiceNotReadyError):
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=_error_body("SERVICE_NOT_READY", "CAGOULE non disponible au démarrage"),
    )


async def file_too_large_handler(request: Request, exc: FileTooLargeError):
    return JSONResponse(
        status_code=413,
        content=_error_body("FILE_TOO_LARGE", str(exc)),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    first_error = exc.errors()[0] if exc.errors() else {}
    details = first_error.get("msg", "Validation échouée")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=_error_body("INVALID_REQUEST", "Requête invalide ou champ manquant", details),
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_body("HTTP_ERROR", str(exc.detail)),
    )


async def internal_error_handler(request: Request, exc: Exception):
    logger.exception("Erreur interne inattendue: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_error_body(
            "INTERNAL_ERROR",
            "Erreur interne inattendue",
            "Consulter les logs serveur pour le stacktrace complet",
        ),
    )
