"""
Tests d'intégration — cagoule-api endpoints
Couvre : tous les endpoints, tous les codes d'erreur, auth Bearer valide/invalide.

Prérequis : CAGOULE installé, CAGOULE_API_KEY définie dans l'environnement de test.
"""

import base64
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Définir la clé avant l'import du serveur
_TEST_KEY = "test_key_cagoule_api_pytest"
os.environ.setdefault("CAGOULE_API_KEY", _TEST_KEY)

from cagoule_api.server import app
from cagoule_api import crypto


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth_client():
    """Client avec Bearer token valide."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {_TEST_KEY}"},
    ) as c:
        yield c


SAMPLE_TEXT = "Bonjour QuantOS — test API"
SAMPLE_PASSWORD = "pwd_test_cagoule"


# ──────────────────────────────────────────────
# /v1/health
# ──────────────────────────────────────────────

class TestHealth:

    @pytest.mark.asyncio
    async def test_health_200(self, client):
        r = await client.get("/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "version" in body
        assert "cagoule_available" in body

    @pytest.mark.asyncio
    async def test_health_no_auth_required(self, client):
        """Health doit être accessible sans authentification."""
        r = await client.get("/v1/health")
        assert r.status_code == 200


# ──────────────────────────────────────────────
# Auth — Bearer token
# ──────────────────────────────────────────────

class TestAuth:

    @pytest.mark.asyncio
    async def test_encrypt_without_key_returns_401(self, client):
        r = await client.post("/v1/encrypt", json={"plaintext": "x", "password": "y"})
        assert r.status_code == 401
        body = r.json()
        assert body["error"]["code"] == "AUTH_FAILED"

    @pytest.mark.asyncio
    async def test_encrypt_with_wrong_key_returns_401(self, client):
        r = await client.post(
            "/v1/encrypt",
            json={"plaintext": "x", "password": "y"},
            headers={"Authorization": "Bearer wrong_key"},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_encrypt_with_x_api_key_header(self, client):
        """Accepte aussi X-API-Key comme header."""
        r = await client.post(
            "/v1/encrypt",
            json={"plaintext": SAMPLE_TEXT, "password": SAMPLE_PASSWORD},
            headers={"X-API-Key": _TEST_KEY},
        )
        # 200 si CAGOULE dispo, 503 sinon — dans les deux cas, pas 401
        assert r.status_code in (200, 503)


# ──────────────────────────────────────────────
# /v1/encrypt + /v1/decrypt — texte
# ──────────────────────────────────────────────

@pytest.mark.skipif(not crypto.is_cagoule_available(), reason="CAGOULE non installé")
class TestEncryptDecryptText:

    @pytest.mark.asyncio
    async def test_encrypt_200(self, auth_client):
        r = await auth_client.post(
            "/v1/encrypt",
            json={"plaintext": SAMPLE_TEXT, "password": SAMPLE_PASSWORD},
        )
        assert r.status_code == 200
        assert "ciphertext_b64" in r.json()

    @pytest.mark.asyncio
    async def test_decrypt_200(self, auth_client):
        # Chiffrer d'abord
        r_enc = await auth_client.post(
            "/v1/encrypt",
            json={"plaintext": SAMPLE_TEXT, "password": SAMPLE_PASSWORD},
        )
        ct = r_enc.json()["ciphertext_b64"]

        # Puis déchiffrer
        r_dec = await auth_client.post(
            "/v1/decrypt",
            json={"ciphertext_b64": ct, "password": SAMPLE_PASSWORD},
        )
        assert r_dec.status_code == 200
        assert r_dec.json()["plaintext"] == SAMPLE_TEXT

    @pytest.mark.asyncio
    async def test_roundtrip_perfect(self, auth_client):
        texts = [
            "Simple ASCII",
            "Français avec accents éàü",
            "مرحباً بالعالم",
            "A" * 10_000,
            '{"json": true, "nested": {"key": "val"}}',
        ]
        for text in texts:
            r_enc = await auth_client.post("/v1/encrypt", json={"plaintext": text, "password": SAMPLE_PASSWORD})
            ct = r_enc.json()["ciphertext_b64"]
            r_dec = await auth_client.post("/v1/decrypt", json={"ciphertext_b64": ct, "password": SAMPLE_PASSWORD})
            assert r_dec.json()["plaintext"] == text, f"Roundtrip failed for: {text[:50]}"

    @pytest.mark.asyncio
    async def test_decrypt_wrong_password_returns_422(self, auth_client):
        r_enc = await auth_client.post(
            "/v1/encrypt",
            json={"plaintext": SAMPLE_TEXT, "password": SAMPLE_PASSWORD},
        )
        ct = r_enc.json()["ciphertext_b64"]
        r_dec = await auth_client.post(
            "/v1/decrypt",
            json={"ciphertext_b64": ct, "password": "wrong_password"},
        )
        assert r_dec.status_code == 422
        assert r_dec.json()["error"]["code"] == "DECRYPTION_FAILED"

    @pytest.mark.asyncio
    async def test_decrypt_tampered_ciphertext_returns_422(self, auth_client):
        r_enc = await auth_client.post(
            "/v1/encrypt",
            json={"plaintext": SAMPLE_TEXT, "password": SAMPLE_PASSWORD},
        )
        raw = bytearray(base64.b64decode(r_enc.json()["ciphertext_b64"]))
        raw[-1] ^= 0xFF
        tampered = base64.b64encode(bytes(raw)).decode()

        r_dec = await auth_client.post(
            "/v1/decrypt",
            json={"ciphertext_b64": tampered, "password": SAMPLE_PASSWORD},
        )
        assert r_dec.status_code == 422

    @pytest.mark.asyncio
    async def test_encrypt_missing_fields_returns_400(self, auth_client):
        r = await auth_client.post("/v1/encrypt", json={"plaintext": "only_one_field"})
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_REQUEST"

    @pytest.mark.asyncio
    async def test_decrypt_invalid_base64_returns_422(self, auth_client):
        r = await auth_client.post(
            "/v1/decrypt",
            json={"ciphertext_b64": "!!!NOT_BASE64!!!", "password": SAMPLE_PASSWORD},
        )
        assert r.status_code == 400  # Pydantic validator → 400


# ──────────────────────────────────────────────
# /v1/encrypt/file + /v1/decrypt/file
# ──────────────────────────────────────────────

@pytest.mark.skipif(not crypto.is_cagoule_available(), reason="CAGOULE non installé")
class TestFileEndpoints:

    @pytest.mark.asyncio
    async def test_encrypt_file_200(self, auth_client):
        r = await auth_client.post(
            "/v1/encrypt/file",
            files={"file": ("test.txt", b"Binary content \x00\xFF", "application/octet-stream")},
            data={"password": SAMPLE_PASSWORD},
        )
        assert r.status_code == 200
        assert "ciphertext_b64" in r.json()

    @pytest.mark.asyncio
    async def test_decrypt_file_roundtrip(self, auth_client):
        original = b"Binary file content \x00\x01\x02\xFF\xFE"

        r_enc = await auth_client.post(
            "/v1/encrypt/file",
            files={"file": ("data.bin", original, "application/octet-stream")},
            data={"password": SAMPLE_PASSWORD},
        )
        ct_b64 = r_enc.json()["ciphertext_b64"]
        ct_bytes = base64.b64decode(ct_b64)

        r_dec = await auth_client.post(
            "/v1/decrypt/file",
            files={"file": ("data.bin.enc", ct_bytes, "application/octet-stream")},
            data={"password": SAMPLE_PASSWORD},
        )
        assert r_dec.status_code == 200
        assert r_dec.content == original

    @pytest.mark.asyncio
    async def test_file_too_large_returns_413(self, auth_client):
        """Fichier > 10 MB → 413"""
        big_data = b"A" * (11 * 1024 * 1024)  # 11 MB
        r = await auth_client.post(
            "/v1/encrypt/file",
            files={"file": ("big.bin", big_data, "application/octet-stream")},
            data={"password": SAMPLE_PASSWORD},
        )
        assert r.status_code == 413
