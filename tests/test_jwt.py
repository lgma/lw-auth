import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from lw_auth.jwt import verify_token
from lw_auth.schemas import TokenPayload

# Keypair efímero para tests
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_KEY = _private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
).decode()
PUBLIC_KEY = _private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()


def _make_token(payload: dict) -> str:
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


class TestVerifyToken:
    def test_valid_token(self):
        payload = {
            "sub": "42",
            "role": "legal_user",
            "org_id": "550e8400-e29b-41d4-a716-446655440000",
            "type": "access",
            "exp": int(time.time()) + 1800,
            "iat": int(time.time()),
        }
        token = _make_token(payload)
        result = verify_token(token, PUBLIC_KEY)
        assert isinstance(result, TokenPayload)
        assert result.sub == "42"
        assert result.role == "legal_user"
        assert result.org_id == "550e8400-e29b-41d4-a716-446655440000"

    def test_email_in_payload(self):
        payload = {
            "sub": "42",
            "role": "legal_admin",
            "email": "abogado@firma.com",
            "org_id": "7",
            "type": "access",
            "exp": int(time.time()) + 1800,
            "iat": int(time.time()),
        }
        result = verify_token(_make_token(payload), PUBLIC_KEY)
        assert result.email == "abogado@firma.com"

    def test_email_optional_absent(self):
        payload = {
            "sub": "1",
            "role": "admin",
            "org_id": None,
            "type": "access",
            "exp": int(time.time()) + 1800,
            "iat": int(time.time()),
        }
        result = verify_token(_make_token(payload), PUBLIC_KEY)
        assert result.email is None

    def test_no_org_id(self):
        payload = {
            "sub": "1",
            "role": "admin",
            "org_id": None,
            "type": "access",
            "exp": int(time.time()) + 1800,
            "iat": int(time.time()),
        }
        result = verify_token(_make_token(payload), PUBLIC_KEY)
        assert result.org_id is None

    def test_expired_token(self):
        payload = {
            "sub": "1",
            "role": "admin",
            "org_id": None,
            "type": "access",
            "exp": int(time.time()) - 10,  # ya expiró
            "iat": int(time.time()) - 1810,
        }
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_token(_make_token(payload), PUBLIC_KEY)

    def test_wrong_key(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_public = other_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        payload = {
            "sub": "1", "role": "admin", "org_id": None,
            "type": "access",
            "exp": int(time.time()) + 1800,
            "iat": int(time.time()),
        }
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(_make_token(payload), other_public)

    def test_tampered_token(self):
        payload = {
            "sub": "1", "role": "admin", "org_id": None,
            "type": "access",
            "exp": int(time.time()) + 1800,
            "iat": int(time.time()),
        }
        token = _make_token(payload)
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(tampered, PUBLIC_KEY)


class TestJWKSClient:
    def test_jwks_verifies_token_with_kid(self):
        from lw_auth import JWKSClient
        from lw_auth.jwt import JWKSClient as _JC

        # Build a fake JWKS dict (in-memory) and inject it
        client = _JC.__new__(_JC)
        client.jwks_url = "fake://"
        client.cache_ttl = 3600
        client._keys = {"k1": PUBLIC_KEY}
        client._fetched_at = time.time()

        token = jwt.encode(
            {
                "sub": "1", "role": "admin", "type": "access",
                "exp": int(time.time()) + 1800, "iat": int(time.time()),
            },
            PRIVATE_KEY, algorithm="RS256", headers={"kid": "k1"},
        )
        result = verify_token(token, jwks=client)
        assert result.sub == "1"

    def test_jwks_missing_kid_raises(self):
        from lw_auth.jwt import JWKSClient as _JC
        client = _JC.__new__(_JC)
        client.jwks_url = "fake://"
        client.cache_ttl = 3600
        client._keys = {"k1": PUBLIC_KEY}
        client._fetched_at = time.time()

        # token WITHOUT kid header
        token = _make_token({
            "sub": "1", "role": "admin", "type": "access",
            "exp": int(time.time()) + 1800, "iat": int(time.time()),
        })
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(token, jwks=client)


class TestStrictValidation:
    def test_issuer_validation_passes(self):
        token = _make_token({
            "sub": "1", "role": "admin", "type": "access",
            "iss": "auth.leeuwwolk.com",
            "exp": int(time.time()) + 1800, "iat": int(time.time()),
        })
        result = verify_token(token, PUBLIC_KEY, issuer="auth.leeuwwolk.com")
        assert result.iss == "auth.leeuwwolk.com"

    def test_issuer_validation_rejects_wrong(self):
        token = _make_token({
            "sub": "1", "role": "admin", "type": "access",
            "iss": "evil.com",
            "exp": int(time.time()) + 1800, "iat": int(time.time()),
        })
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(token, PUBLIC_KEY, issuer="auth.leeuwwolk.com")

    def test_expected_type_rejects(self):
        token = _make_token({
            "sub": "1", "role": "admin", "type": "refresh",
            "exp": int(time.time()) + 1800, "iat": int(time.time()),
        })
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(token, PUBLIC_KEY, expected_type="access")


class TestStaffClaim:
    def test_staff_true_se_expone(self):
        payload = {
            "sub": "1", "role": "admin", "type": "access", "staff": True,
            "exp": int(time.time()) + 1800, "iat": int(time.time()),
        }
        result = verify_token(_make_token(payload), PUBLIC_KEY)
        assert result.staff is True

    def test_sin_claim_default_false(self):
        payload = {
            "sub": "42", "role": "legal_user", "type": "access",
            "exp": int(time.time()) + 1800, "iat": int(time.time()),
        }
        result = verify_token(_make_token(payload), PUBLIC_KEY)
        assert result.staff is False
