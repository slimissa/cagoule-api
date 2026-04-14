"""
Wrapper autour des primitives CAGOULE pour cagoule-api.

Règles de sécurité (conformes au DoD v0.1.0) :
  - Jamais de plaintext ni de password dans les logs INFO ou supérieur.
  - Jamais de hash de password dans les logs.
  - Les erreurs de déchiffrement sont retournées via DecryptionFailedError,
    jamais loguées avec le ciphertext complet.
"""

import base64
import logging

from cagoule_api.errors import DecryptionFailedError, ServiceNotReadyError

logger = logging.getLogger("cagoule_api.crypto")

# ──────────────────────────────────────────────
# Import CAGOULE — vérifié au chargement du module
# ──────────────────────────────────────────────

_CAGOULE_AVAILABLE = False
_cagoule_encrypt = None
_cagoule_decrypt = None

try:
    from cagoule import encrypt as _cagoule_encrypt, decrypt as _cagoule_decrypt
    _CAGOULE_AVAILABLE = True
    logger.info("CAGOULE importé avec succès")
except ImportError as _e:
    logger.critical("Impossible d'importer CAGOULE : %s", _e)
except Exception as _e:
    logger.critical("Erreur inattendue lors de l'import CAGOULE : %s", _e)


def _assert_cagoule() -> None:
    if not _CAGOULE_AVAILABLE:
        raise ServiceNotReadyError(
            "CAGOULE n'est pas installé ou importable. "
            "pip install cagoule>=1.5.0"
        )


# ──────────────────────────────────────────────
# API publique
# ──────────────────────────────────────────────

def encrypt_text(plaintext: str, password: str) -> str:
    """
    Chiffre un texte UTF-8 avec CAGOULE.

    Args:
        plaintext: Texte en clair (UTF-8).
        password:  Mot de passe Argon2id.

    Returns:
        Ciphertext encodé en Base64 (str).

    Raises:
        ServiceNotReadyError: Si CAGOULE n'est pas disponible.
        ValueError: Si les entrées sont vides.
    """
    _assert_cagoule()
    
    if not plaintext:
        raise ValueError("plaintext ne peut pas être vide")
    if not password:
        raise ValueError("password ne peut pas être vide")
    
    # Log seulement la taille, jamais le contenu
    logger.debug("encrypt_text: %d octets en entrée", len(plaintext.encode("utf-8")))
    
    try:
        raw_cipher: bytes = _cagoule_encrypt(plaintext.encode("utf-8"), password)
    except Exception as exc:
        logger.error("Erreur CAGOULE inattendue lors du chiffrement", exc_info=True)
        raise
    
    # Base64 standard (RFC 4648)
    return base64.b64encode(raw_cipher).decode("ascii")


def decrypt_text(ciphertext_b64: str, password: str) -> str:
    """
    Déchiffre un ciphertext Base64 avec CAGOULE.

    Args:
        ciphertext_b64: Ciphertext encodé Base64 (str).
        password:       Mot de passe Argon2id.

    Returns:
        Texte déchiffré (UTF-8).

    Raises:
        DecryptionFailedError: Si le tag AEAD est invalide ou le mot de passe incorrect.
        ServiceNotReadyError:  Si CAGOULE n'est pas disponible.
    """
    _assert_cagoule()

    if not ciphertext_b64:
        raise DecryptionFailedError("ciphertext_b64 ne peut pas être vide")
    if not password:
        raise DecryptionFailedError("password ne peut pas être vide")

    try:
        raw_cipher = base64.b64decode(ciphertext_b64, validate=True)
    except Exception as e:
        logger.debug("Base64 invalide reçu", exc_info=True)
        raise DecryptionFailedError(
            "Base64 malformé — impossible de décoder le ciphertext"
        ) from e

    try:
        plaintext_bytes: bytes = _cagoule_decrypt(raw_cipher, password)
    except Exception as exc:
        msg = str(exc).lower()
        # Détection des erreurs d'authentification (AEAD)
        if any(kw in msg for kw in ("tag", "mac", "auth", "invalid", "tamper", "decrypt", "corrupt")):
            raise DecryptionFailedError(
                "Tag d'authentification invalide — le ciphertext a peut-être été altéré "
                "ou le mot de passe est incorrect"
            ) from exc
        # Erreur inattendue — on la remonte sans exposer de détails sensibles
        logger.error("Erreur CAGOULE inattendue lors du déchiffrement", exc_info=True)
        raise

    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise DecryptionFailedError(
            "Le résultat déchiffré n'est pas du texte UTF-8 valide. "
            "Utiliser /v1/decrypt/file pour les fichiers binaires."
        ) from e


def encrypt_bytes(data: bytes, password: str) -> str:
    """
    Chiffre des données binaires arbitraires avec CAGOULE.

    Returns:
        Ciphertext encodé en Base64 (str).
    """
    _assert_cagoule()
    
    if not data:
        logger.debug("encrypt_bytes appelé avec données vides")
    if not password:
        raise ValueError("password ne peut pas être vide")
    
    logger.debug("encrypt_bytes: %d octets en entrée", len(data))
    
    try:
        raw_cipher: bytes = _cagoule_encrypt(data, password)
    except Exception as exc:
        logger.error("Erreur CAGOULE inattendue lors du chiffrement (bytes)", exc_info=True)
        raise
    
    return base64.b64encode(raw_cipher).decode("ascii")


def decrypt_bytes(ciphertext_b64: str, password: str) -> bytes:
    """
    Déchiffre un ciphertext Base64 vers bytes bruts.

    Returns:
        Données déchiffrées (bytes).
    """
    _assert_cagoule()

    if not ciphertext_b64:
        raise DecryptionFailedError("ciphertext_b64 ne peut pas être vide")
    if not password:
        raise DecryptionFailedError("password ne peut pas être vide")

    try:
        raw_cipher = base64.b64decode(ciphertext_b64, validate=True)
    except Exception as e:
        logger.debug("Base64 invalide pour bytes", exc_info=True)
        raise DecryptionFailedError("Base64 malformé") from e

    try:
        return _cagoule_decrypt(raw_cipher, password)
    except Exception as exc:
        msg = str(exc).lower()
        if any(kw in msg for kw in ("tag", "mac", "auth", "invalid", "tamper", "decrypt", "corrupt")):
            raise DecryptionFailedError(
                "Tag d'authentification invalide — ciphertext altéré ou mot de passe incorrect"
            ) from exc
        logger.error("Erreur CAGOULE inattendue (decrypt_bytes)", exc_info=True)
        raise


def is_cagoule_available() -> bool:
    """Retourne True si CAGOULE est disponible."""
    return _CAGOULE_AVAILABLE