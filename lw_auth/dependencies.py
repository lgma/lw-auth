"""
FastAPI dependency para productos FastAPI (Transcriptor, etc.)

Uso:
    from lw_auth.dependencies import make_auth_dependency
    from lw_auth.schemas import TokenPayload

    get_current_user = make_auth_dependency(PUBLIC_KEY)

    @router.get("/me")
    def me(user: TokenPayload = Depends(get_current_user)):
        return {"user_id": user.sub, "role": user.role}
"""

from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from lw_auth.jwt import verify_token
from lw_auth.schemas import TokenPayload


def make_auth_dependency(public_key: str) -> Callable:
    """Devuelve un FastAPI Depends que verifica el JWT y retorna TokenPayload."""
    oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

    def _get_current_user(token: str = Depends(oauth2)) -> TokenPayload:
        try:
            return verify_token(token, public_key)
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )

    return _get_current_user
