"""
Schémas Pydantic v2 pour cagoule-api.
Tous les champs sensibles sont marqués pour exclusion des logs.
"""

from pydantic import BaseModel, Field, field_validator
import base64


# ──────────────────────────────────────────────
# Requêtes
# ──────────────────────────────────────────────

class EncryptRequest(BaseModel):
    plaintext: str = Field(
        ...,
        min_length=1,
        description="Texte en clair à chiffrer (UTF-8)",
    )
    password: str = Field(
        ...,
        min_length=1,
        description="Mot de passe de dérivation (Argon2id)",
    )

    model_config = {"json_schema_extra": {"example": {"plaintext": "Hello QuantOS", "password": "s3cr3t"}}}


class DecryptRequest(BaseModel):
    ciphertext_b64: str = Field(
        ...,
        min_length=1,
        description="Ciphertext encodé en Base64 (issu de /v1/encrypt)",
    )
    password: str = Field(
        ...,
        min_length=1,
        description="Mot de passe de dérivation (Argon2id)",
    )

    @field_validator("ciphertext_b64")
    @classmethod
    def validate_base64(cls, v: str) -> str:
        try:
            base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("ciphertext_b64 n'est pas un Base64 valide")
        return v

    model_config = {"json_schema_extra": {"example": {"ciphertext_b64": "<base64>", "password": "s3cr3t"}}}


# ──────────────────────────────────────────────
# Réponses
# ──────────────────────────────────────────────

class EncryptResponse(BaseModel):
    ciphertext_b64: str = Field(..., description="Ciphertext encodé Base64")


class DecryptResponse(BaseModel):
    plaintext: str = Field(..., description="Texte déchiffré (UTF-8)")


class HealthResponse(BaseModel):
    status: str = Field(default="ok")
    version: str
    cagoule_available: bool


# ──────────────────────────────────────────────
# Erreurs
# ──────────────────────────────────────────────

class ErrorDetail(BaseModel):
    code: str
    message: str
    details: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
