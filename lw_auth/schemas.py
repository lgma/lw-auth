from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: str            # user_id
    role: str           # badge del rol (ej: "admin", "legal_user")
    org_id: str | None  # UUID string o None
    type: str           # "access"
    exp: int
    iat: int
