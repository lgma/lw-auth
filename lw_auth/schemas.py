from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: str                    # user_id
    role: str                   # badge del rol (ej: "admin", "legal_user")
    email: str | None = None    # email del usuario
    org_id: str | None = None   # ID de organización o None
    type: str                   # "access"
    exp: int
    iat: int
