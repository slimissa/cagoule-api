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

try:
    from cagoule import encrypt as _cagoule_encrypt, decrypt as _cagoule_decrypt  # type: ignore
    _CAGOULE_AVAILABLE = True
    logger.info("CAGOULE importé avec succès")
except ImportError as _e:
    _CAGOULE_AVAILABLE = False
    logger.critical("Impossible d'importer CAGOULE : %s", _e)


def _assert_cagoule() -> None:
    if not _CAGOULE_AVAILABLE:
        raise ServiceNotReadyError("CAGOULE n'est pas installé ou importable")


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
        Ciphertext encodé en Base64 URL-safe (str).

    Raises:
        ServiceNotReadyError: Si CAGOULE n'est pas disponible.
        Exception:            Pour toute erreur CAGOULE inattendue.
    """
    _assert_cagoule()
    logger.debug("encrypt_text: %d octets en entrée", len(plaintext.encode()))
    raw_cipher: bytes = _cagoule_encrypt(plaintext.encode("utf-8"), password)
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

    try:
        raw_cipher = base64.b64decode(ciphertext_b64)
    except Exception:
        raise DecryptionFailedError("Base64 malformé — impossible de décoder le ciphertext")

    try:
        plaintext_bytes: bytes = _cagoule_decrypt(raw_cipher, password)
    except Exception as exc:
        msg = str(exc).lower()
        if any(kw in msg for kw in ("tag", "mac", "auth", "invalid", "tamper", "decrypt")):
            raise DecryptionFailedError(
                "Tag d'authentification invalide — le ciphertext a peut-être été altéré "
                "ou le mot de passe est incorrect"
            )
        # Erreur inattendue — on la remonte sans exposer de détails sensibles
        logger.error("Erreur CAGOULE inattendue lors du déchiffrement (type: %s)", type(exc).__name__)
        raise

    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionFailedError(
            "Le résultat déchiffré n'est pas du texte UTF-8 valide. "
            "Utiliser /v1/decrypt/file pour les fichiers binaires."
        )


def encrypt_bytes(data: bytes, password: str) -> str:
    """
    Chiffre des données binaires arbitraires avec CAGOULE.

    Returns:
        Ciphertext encodé en Base64 (str).
    """
    _assert_cagoule()
    logger.debug("encrypt_bytes: %d octets en entrée", len(data))
    raw_cipher: bytes = _cagoule_encrypt(data, password)
    return base64.b64encode(raw_cipher).decode("ascii")


def decrypt_bytes(ciphertext_b64: str, password: str) -> bytes:
    """
    Déchiffre un ciphertext Base64 vers bytes bruts.

    Returns:
        Données déchiffrées (bytes).
    """
    _assert_cagoule()

    try:
        raw_cipher = base64.b64decode(ciphertext_b64)
    except Exception:
        raise DecryptionFailedError("Base64 malformé")

    try:
        return _cagoule_decrypt(raw_cipher, password)
    except Exception as exc:
        msg = str(exc).lower()
        if any(kw in msg for kw in ("tag", "mac", "auth", "invalid", "tamper", "decrypt")):
            raise DecryptionFailedError(
                "Tag d'authentification invalide — ciphertext altéré ou mot de passe incorrect"
            )
        logger.error("Erreur CAGOULE inattendue (bytes, type: %s)", type(exc).__name__)
        raise


def is_cagoule_available() -> bool:
    return _CAGOULE_AVAILABLE
