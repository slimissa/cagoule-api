"""
Tests unitaires — cagoule_api.crypto
Roundtrip, tag invalide, base64 malformé, fichiers binaires.

Prérequis : CAGOULE installé (pip install cagoule>=1.5.0)
"""

import base64
import pytest
import time
from unittest.mock import patch

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

    def test_empty_plaintext_raises(self):
        """Le chiffrement de texte vide doit être refusé"""
        with pytest.raises(ValueError, match="plaintext ne peut pas être vide"):
            crypto.encrypt_text("", SAMPLE_PASSWORD)

    def test_empty_password_raises(self):
        """Le mot de passe vide doit être refusé"""
        with pytest.raises((ValueError, DecryptionFailedError)):
            crypto.encrypt_text(SAMPLE_TEXT, "")

    def test_performance(self):
        """Le chiffrement doit être rapide (< 0.5s pour 1KB)"""
        text = "A" * 1024
        start = time.perf_counter()
        ct = crypto.encrypt_text(text, SAMPLE_PASSWORD)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, f"Trop lent: {elapsed:.3f}s"


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

    def test_ciphertext_without_signature_raises(self):
        """Ciphertext qui ne commence pas par CGL doit lever une erreur"""
        fake_cipher = base64.b64encode(b"fake_data").decode()
        with pytest.raises((DecryptionFailedError, Exception)):
            crypto.decrypt_text(fake_cipher, SAMPLE_PASSWORD)


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

    def test_empty_bytes(self):
        """Le chiffrement de bytes vides doit fonctionner"""
        ct = crypto.encrypt_bytes(b"", SAMPLE_PASSWORD)
        pt = crypto.decrypt_bytes(ct, SAMPLE_PASSWORD)
        assert pt == b""


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

    def test_encrypt_bytes_raises_when_unavailable(self):
        with patch.object(crypto, "_CAGOULE_AVAILABLE", False):
            with pytest.raises(ServiceNotReadyError):
                crypto.encrypt_bytes(b"test", "pwd")

    def test_decrypt_bytes_raises_when_unavailable(self):
        with patch.object(crypto, "_CAGOULE_AVAILABLE", False):
            with pytest.raises(ServiceNotReadyError):
                crypto.decrypt_bytes(base64.b64encode(b"fake").decode(), "pwd")
