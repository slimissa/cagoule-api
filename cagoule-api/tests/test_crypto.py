"""
Tests unitaires — cagoule_api.crypto
Roundtrip, tag invalide, base64 malformé, fichiers binaires.

Prérequis : CAGOULE installé (pip install cagoule>=1.5.0)
"""

import base64
import pytest
from unittest.mock import patch, MagicMock

from cagoule_api import crypto
from cagoule_api.errors import DecryptionFailedError, ServiceNotReadyError


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

SAMPLE_TEXT = "Hello QuantOS — test CAGOULE API 🔐"
SAMPLE_PASSWORD = "supersecret_argon2"
SAMPLE_BYTES = b"\x00\x01\x02\xFF\xFE binary data"


# ──────────────────────────────────────────────
# Tests roundtrip texte
# ──────────────────────────────────────────────

@pytest.mark.skipif(not crypto.is_cagoule_available(), reason="CAGOULE non installé")
class TestEncryptDecryptText:

    def test_roundtrip_basic(self):
        ct = crypto.encrypt_text(SAMPLE_TEXT, SAMPLE_PASSWORD)
        pt = crypto.decrypt_text(ct, SAMPLE_PASSWORD)
        assert pt == SAMPLE_TEXT

    def test_ciphertext_is_base64(self):
        ct = crypto.encrypt_text(SAMPLE_TEXT, SAMPLE_PASSWORD)
        decoded = base64.b64decode(ct)
        assert len(decoded) > 0

    def test_ciphertext_differs_each_call(self):
        """CAGOULE doit utiliser un nonce aléatoire — deux chiffrements ≠"""
        ct1 = crypto.encrypt_text(SAMPLE_TEXT, SAMPLE_PASSWORD)
        ct2 = crypto.encrypt_text(SAMPLE_TEXT, SAMPLE_PASSWORD)
        assert ct1 != ct2

    def test_wrong_password_raises(self):
        ct = crypto.encrypt_text(SAMPLE_TEXT, SAMPLE_PASSWORD)
        with pytest.raises(DecryptionFailedError):
            crypto.decrypt_text(ct, "wrong_password")

    def test_unicode_text(self):
        text = "مرحباً — Bonjour — 日本語 — Ελληνικά"
        ct = crypto.encrypt_text(text, SAMPLE_PASSWORD)
        pt = crypto.decrypt_text(ct, SAMPLE_PASSWORD)
        assert pt == text

    def test_long_text(self):
        text = "A" * 100_000
        ct = crypto.encrypt_text(text, SAMPLE_PASSWORD)
        pt = crypto.decrypt_text(ct, SAMPLE_PASSWORD)
        assert pt == text


# ──────────────────────────────────────────────
# Tests erreurs déchiffrement
# ──────────────────────────────────────────────

@pytest.mark.skipif(not crypto.is_cagoule_available(), reason="CAGOULE non installé")
class TestDecryptionErrors:

    def test_tampered_ciphertext_raises(self):
        ct_b64 = crypto.encrypt_text(SAMPLE_TEXT, SAMPLE_PASSWORD)
        raw = bytearray(base64.b64decode(ct_b64))
        raw[-1] ^= 0xFF  # Flip dernier bit
        tampered_b64 = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(DecryptionFailedError):
            crypto.decrypt_text(tampered_b64, SAMPLE_PASSWORD)

    def test_malformed_base64_raises(self):
        with pytest.raises(DecryptionFailedError):
            crypto.decrypt_text("!!!not_base64!!!", SAMPLE_PASSWORD)

    def test_empty_ciphertext_raises(self):
        empty_b64 = base64.b64encode(b"").decode()
        with pytest.raises((DecryptionFailedError, Exception)):
            crypto.decrypt_text(empty_b64, SAMPLE_PASSWORD)


# ──────────────────────────────────────────────
# Tests roundtrip binaire
# ──────────────────────────────────────────────

@pytest.mark.skipif(not crypto.is_cagoule_available(), reason="CAGOULE non installé")
class TestEncryptDecryptBytes:

    def test_roundtrip_binary(self):
        ct = crypto.encrypt_bytes(SAMPLE_BYTES, SAMPLE_PASSWORD)
        pt = crypto.decrypt_bytes(ct, SAMPLE_PASSWORD)
        assert pt == SAMPLE_BYTES

    def test_roundtrip_null_bytes(self):
        data = b"\x00" * 1024
        ct = crypto.encrypt_bytes(data, SAMPLE_PASSWORD)
        pt = crypto.decrypt_bytes(ct, SAMPLE_PASSWORD)
        assert pt == data

    def test_roundtrip_large_binary(self):
        import os
        data = os.urandom(5 * 1024 * 1024)  # 5 MB
        ct = crypto.encrypt_bytes(data, SAMPLE_PASSWORD)
        pt = crypto.decrypt_bytes(ct, SAMPLE_PASSWORD)
        assert pt == data


# ──────────────────────────────────────────────
# Tests ServiceNotReady (mock)
# ──────────────────────────────────────────────

class TestServiceNotReady:

    def test_encrypt_raises_when_cagoule_unavailable(self):
        with patch.object(crypto, "_CAGOULE_AVAILABLE", False):
            with pytest.raises(ServiceNotReadyError):
                crypto.encrypt_text("test", "pwd")

    def test_decrypt_raises_when_cagoule_unavailable(self):
        with patch.object(crypto, "_CAGOULE_AVAILABLE", False):
            with pytest.raises(ServiceNotReadyError):
                crypto.decrypt_text(base64.b64encode(b"fake").decode(), "pwd")
