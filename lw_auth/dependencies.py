"""FastAPI dependency factory.

Usage:
    from lw_auth import JWKSClient
    from lw_auth.dependencies import make_auth_dependency

    # Modo JWKS (recomendado)
    jwks = JWKSClient("https://auth.leeuwwolk.com/.well-known/jwks.json")
    get_current_user = make_auth_dependency(jwks=jwks)

    # Modo PEM (legacy)
    get_current_user = make_auth_dependency(public_key=PEM_STR)

    @router.get("/me")
    def me(user: TokenPayload = Depends(get_current_user)):
        return {"user_id": user.sub, "role": user.role}
"""
from typing import Callable

import jwt as pyjwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from lw_auth.jwt import JWKSClient, verify_token
from lw_auth.schemas import TokenPayload


def make_auth_dependency(
    *,
    public_key: str | None = None,
    jwks: JWKSClient | None = None,
    issuer: str | None = "auth.leeuwwolk.com",
) -> Callable:
    """Return a FastAPI Depends that verifies the JWT and returns TokenPayload."""
    if public_key is None and jwks is None:
        raise ValueError("Provide public_key or jwks")

    oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

    def _get_current_user(token: str = Depends(oauth2)) -> TokenPayload:
        try:
            return verify_token(token, public_key=public_key, jwks=jwks, issuer=issuer)
        except pyjwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except pyjwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    return _get_current_user
