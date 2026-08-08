from pydantic import BaseModel


class TokenPayload(BaseModel):
    sub: str                            # user_id
    role: str                           # rol (badge global o role_in_org)
    type: str                           # "access"
    exp: int
    iat: int
    iss: str | None = None              # issuer
    jti: str | None = None              # token id
    email: str | None = None
    email_verified: bool | None = None
    org_id: str | None = None
    # Personal de la plataforma Leeuwwolk (rol global admin en auth). Trátalo
    # como superadmin local SIN fila en tu BD; el tenant que opera se elige en
    # pantalla, no con su org_id. Audita sus acciones. Ver INTEGRACION.md §4.1.
    staff: bool = False
