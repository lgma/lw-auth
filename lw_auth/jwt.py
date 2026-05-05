"""JWT verification helpers.

Two modes:

1. Static PEM (legacy):
   ```
   from lw_auth import verify_token
   payload = verify_token(token, public_key=PEM_STR)
   ```

2. Dynamic JWKS (recommended):
   ```
   from lw_auth import JWKSClient, verify_token
   client = JWKSClient("https://auth.leeuwwolk.com/.well-known/jwks.json")
   payload = verify_token(token, jwks=client)
   ```

JWKS mode caches keys for 1h by default and re-fetches on unknown kid.
"""
import json
import time
import urllib.request

import jwt as pyjwt

from lw_auth.schemas import TokenPayload

ALGORITHM = "RS256"
DEFAULT_ISSUER = "auth.leeuwwolk.com"
DEFAULT_CACHE_TTL = 3600  # 1 hour


class JWKSError(Exception):
    pass


class JWKSClient:
    """Lazy-loading JWKS fetcher with TTL cache.

    Refreshes on cache expiry OR when a token presents an unknown kid.
    """

    def __init__(self, jwks_url: str, cache_ttl: int = DEFAULT_CACHE_TTL):
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self._keys: dict[str, str] = {}  # kid → PEM string
        self._fetched_at: float = 0.0

    def _fetch(self) -> None:
        with urllib.request.urlopen(self.jwks_url, timeout=5) as resp:
            data = json.loads(resp.read())
        keys: dict[str, str] = {}
        for jwk in data.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            algo = pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            # Convert public key object to PEM string for caching
            from cryptography.hazmat.primitives import serialization
            pem = algo.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
            keys[kid] = pem
        if not keys:
            raise JWKSError(f"No keys found in JWKS at {self.jwks_url}")
        self._keys = keys
        self._fetched_at = time.time()

    def get_key(self, kid: str) -> str:
        # Refresh on cache miss or expiry
        if (
            kid not in self._keys
            or (time.time() - self._fetched_at) > self.cache_ttl
        ):
            self._fetch()
        if kid not in self._keys:
            raise JWKSError(f"Unknown kid: {kid}")
        return self._keys[kid]


def verify_token(
    token: str,
    public_key: str | None = None,
    *,
    jwks: JWKSClient | None = None,
    issuer: str | None = None,
    expected_type: str | None = None,
) -> TokenPayload:
    """Verify a JWT issued by auth_fastapi.

    Pass either `public_key` (static PEM) or `jwks` (dynamic JWKSClient).
    `issuer` and `expected_type` default to None (no extra validation) to keep
    backward compatibility. New code should pass `issuer="auth.leeuwwolk.com"`
    and `expected_type="access"` for stricter validation.
    """
    if public_key is None and jwks is None:
        raise ValueError("Provide public_key or jwks")

    if jwks is not None:
        header = pyjwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise pyjwt.InvalidTokenError("Token is missing 'kid' header")
        key = jwks.get_key(kid)
    else:
        key = public_key

    options = {"verify_iss": bool(issuer)}
    decode_kwargs = {"algorithms": [ALGORITHM], "options": options}
    if issuer:
        decode_kwargs["issuer"] = issuer

    payload = pyjwt.decode(token, key, **decode_kwargs)

    if expected_type is not None and payload.get("type") != expected_type:
        raise pyjwt.InvalidTokenError(
            f"Invalid token type, expected {expected_type}"
        )

    return TokenPayload(**payload)
