"""
Handlers d'exceptions HTTP pour cagoule-api.
Chaque erreur métier retourne un JSON structuré conforme à l'ADR-05.
"""

import logging
from typing import Optional
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
    pass


class DecryptionFailedError(Exception):
    """Tag AEAD invalide ou mot de passe incorrect."""
    
    def __init__(self, details: Optional[str] = None):
        self.details = details or "Tag d'authentification invalide ou mot de passe incorrect"
        super().__init__(self.details)


class ServiceNotReadyError(Exception):
    """CAGOULE non importable au démarrage."""
    pass


class FileTooLargeError(Exception):
    """Fichier dépasse la limite configurée."""
    pass


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _error_body(code: str, message: str, details: Optional[str] = None) -> dict:
    """Construit le corps d'erreur JSON standardisé."""
    payload = {"code": code, "message": message}
    if details:
        payload["details"] = details
    return {"error": payload}


# ──────────────────────────────────────────────
# Handlers à enregistrer sur l'app FastAPI
# ──────────────────────────────────────────────

async def auth_failed_handler(request: Request, exc: AuthFailedError):
    """401 - Authentification échouée."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=_error_body("AUTH_FAILED", "API key absente ou invalide"),
        headers={"WWW-Authenticate": "Bearer"},
    )


async def decryption_failed_handler(request: Request, exc: DecryptionFailedError):
    """
    422 - Déchiffrement impossible.
    Conforme ADR-05 : requête bien formée mais opération échoue.
    """
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_error_body("DECRYPTION_FAILED", "Déchiffrement impossible", exc.details),
    )


async def service_not_ready_handler(request: Request, exc: ServiceNotReadyError):
    """503 - Service CAGOULE non disponible."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=_error_body("SERVICE_NOT_READY", "CAGOULE non disponible. Vérifier l'installation."),
    )


async def file_too_large_handler(request: Request, exc: FileTooLargeError):
    """413 - Fichier trop volumineux."""
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content=_error_body("FILE_TOO_LARGE", str(exc)),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    422 - Erreur de validation Pydantic.
    Retourne le premier champ en erreur pour faciliter le débogage.
    """
    errors = exc.errors()
    
    if errors:
        first_error = errors[0]
        # Récupérer le champ en erreur
        field_parts = [str(loc) for loc in first_error.get("loc", []) if loc != "body"]
        field = " -> ".join(field_parts) if field_parts else "unknown"
        msg = first_error.get("msg", "Validation échouée")
        details = f"{field}: {msg}" if field else msg
    else:
        details = "Erreur de validation des données"
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=_error_body("VALIDATION_ERROR", "Erreur de validation des données", details),
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Gère les exceptions HTTP génériques (404, 405, etc.)."""
    # Ne pas exposer les détails des erreurs serveur
    if exc.status_code >= 500:
        message = "Erreur interne du serveur"
        logger.warning(f"HTTP {exc.status_code}: {exc.detail}")
    else:
        message = str(exc.detail)
    
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_body(f"HTTP_{exc.status_code}", message),
    )


async def internal_error_handler(request: Request, exc: Exception):
    """
    500 - Erreur interne inattendue.
    Log complet avec stacktrace, mais exposition minimale au client.
    """
    logger.exception("Erreur interne inattendue: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_error_body(
            "INTERNAL_ERROR",
            "Erreur interne inattendue",
            "Consulter les logs serveur pour le stacktrace complet",
        ),
    )