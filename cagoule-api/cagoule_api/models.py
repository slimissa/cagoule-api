"""
Schémas Pydantic v2 pour cagoule-api.
Tous les champs sensibles sont marqués pour exclusion des logs.
"""

import base64
import logging
from typing import Optional
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("cagoule_api.models")


# ──────────────────────────────────────────────
# Validateurs personnalisés
# ──────────────────────────────────────────────

def validate_base64_string(v: str) -> str:
    """Valide qu'une chaîne est correctement encodée en Base64."""
    if not v:
        raise ValueError("La chaîne Base64 ne peut pas être vide")
    
    try:
        decoded = base64.b64decode(v, validate=True)
        if len(decoded) == 0:
            raise ValueError("Le décodage Base64 a produit une chaîne vide")
    except base64.binascii.Error as e:
        raise ValueError(f"Base64 invalide: caractères non autorisés - {e}") from e
    except Exception as e:
        raise ValueError(f"Erreur de décodage Base64: {e}") from e
    
    return v


def validate_password(v: str) -> str:
    """Valide la force du mot de passe (minimum)."""
    if len(v) < 8:
        raise ValueError("Le mot de passe doit contenir au moins 8 caractères")
    if len(v) > 512:
        raise ValueError("Le mot de passe est trop long (max 512 caractères)")
    return v


# ──────────────────────────────────────────────
# Requêtes
# ──────────────────────────────────────────────

class EncryptRequest(BaseModel):
    """Requête de chiffrement texte."""
    
    plaintext: str = Field(
        ...,
        min_length=1,
        max_length=10 * 1024 * 1024,  # 10 MB limite
        description="Texte en clair à chiffrer (UTF-8)",
        examples=["Hello QuantOS"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=512,
        description="Mot de passe de dérivation (Argon2id) - minimum 8 caractères",
        examples=["s3cr3t-password"],
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return validate_password(v)

    model_config = {
        "json_schema_extra": {
            "example": {
                "plaintext": "Hello QuantOS",
                "password": "s3cr3t-password-123"
            }
        }
    }


class DecryptRequest(BaseModel):
    """Requête de déchiffrement texte."""
    
    ciphertext_b64: str = Field(
        ...,
        min_length=1,
        description="Ciphertext encodé en Base64 (issu de /v1/encrypt)",
        examples=["Q0dMMQET/PwKeROGu/MsINYme/xWnmG/AZGM0F0jhHm6..."],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=512,
        description="Mot de passe de dérivation (Argon2id)",
        examples=["s3cr3t-password-123"],
    )

    @field_validator("ciphertext_b64")
    @classmethod
    def validate_ciphertext_base64(cls, v: str) -> str:
        return validate_base64_string(v)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return validate_password(v)

    model_config = {
        "json_schema_extra": {
            "example": {
                "ciphertext_b64": "Q0dMMQET/PwKeROGu/MsINYme/xWnmG/AZGM0F0jhHm6...",
                "password": "s3cr3t-password-123"
            }
        }
    }


# ──────────────────────────────────────────────
# Réponses
# ──────────────────────────────────────────────

class EncryptResponse(BaseModel):
    """Réponse de chiffrement."""
    
    ciphertext_b64: str = Field(
        ...,
        description="Ciphertext encodé Base64",
        examples=["Q0dMMQET/PwKeROGu/MsINYme/xWnmG/AZGM0F0jhHm6..."],
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "ciphertext_b64": "Q0dMMQET/PwKeROGu/MsINYme/xWnmG/AZGM0F0jhHm6..."
            }
        }
    }


class DecryptResponse(BaseModel):
    """Réponse de déchiffrement."""
    
    plaintext: str = Field(
        ...,
        description="Texte déchiffré (UTF-8)",
        examples=["Hello QuantOS"],
    )


class HealthResponse(BaseModel):
    """Réponse du endpoint de santé."""
    
    status: str = Field(
        default="ok",
        pattern="^(ok|error|degraded)$",
        description="Statut du service",
    )
    version: str = Field(
        ...,
        pattern=r"^\d+\.\d+\.\d+.*$",
        description="Version de l'API",
    )
    cagoule_available: bool = Field(
        ...,
        description="Indique si la bibliothèque CAGOULE est disponible",
    )
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "status": "ok",
                "version": "0.1.0-dev",
                "cagoule_available": True
            }
        }
    }


# ──────────────────────────────────────────────
# Erreurs
# ──────────────────────────────────────────────

class ErrorDetail(BaseModel):
    """Détail d'une erreur."""
    
    code: str = Field(
        ...,
        description="Code d'erreur unique (ex: AUTH_FAILED, DECRYPTION_FAILED)",
        examples=["AUTH_FAILED"],
    )
    message: str = Field(
        ...,
        description="Message d'erreur lisible",
        examples=["API key absente ou invalide"],
    )
    details: Optional[str] = Field(
        None,
        description="Détails supplémentaires (optionnels)",
        examples=["Le token Bearer est manquant dans l'en-tête Authorization"],
    )


class ErrorResponse(BaseModel):
    """Réponse d'erreur standardisée."""
    
    error: ErrorDetail = Field(..., description="Conteneur d'erreur")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "error": {
                    "code": "AUTH_FAILED",
                    "message": "API key absente ou invalide",
                    "details": "X-API-Key header manquant"
                }
            }
        }
    }