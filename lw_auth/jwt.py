import jwt

from lw_auth.schemas import TokenPayload

ALGORITHM = "RS256"


def verify_token(token: str, public_key: str) -> TokenPayload:
    """
    Verifica un JWT RS256 emitido por auth_fastapi.

    Args:
        token:      JWT string (sin el prefijo "Bearer ")
        public_key: Contenido PEM de la public key de Leeuwwolk

    Returns:
        TokenPayload con los campos del JWT

    Raises:
        jwt.ExpiredSignatureError: si el token expiró
        jwt.InvalidTokenError:     si el token es inválido
    """
    payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])
    return TokenPayload(**payload)
