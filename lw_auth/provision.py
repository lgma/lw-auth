"""Alta de clientes desde los productos (org + identidad + apikey).

Tres llamadas idempotentes: reintentar un alta fallida es seguro y no duplica nada.

    from lw_auth import ProvisionClient

    prov = ProvisionClient(
        auth_url="https://auth.leeuwwolk.com",
        gatekeeper_url="https://gatekeeper.leeuwwolk.com",
        auth_token_provider=lambda: request.cookies.get("access_token", ""),
        gatekeeper_api_key=os.environ["GATEKEEPER_SERVICE_KEY"],
    )

    org = prov.ensure_org("SOFOM Acme", "sofom-acme")           # → org.org_id
    ident = prov.ensure_identity("dir@acme.mx", role="legal_admin", org_id=org.org_id)
    key = prov.ensure_apikey(org.org_id, "sofom-acme-api", scopes=["legalops:read"])
    # key.secret solo viene en created/rotated; en "exists" es None (usa rotate_apikey).

El producto escribe su org/roles/permisos en SU BD local — auth solo da identidad
y gatekeeper solo apikeys. Ver `auth_fastapi/docs/PLAN_ALTA_CLIENTES.md`.
"""
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lw_auth._version import __version__

USER_AGENT = f"lw-auth/{__version__} (+https://github.com/lgma/lw-auth)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_EXPIRES_DAYS = 365


class ProvisionError(Exception):
    """Error al aprovisionar. `status_code` es None si nunca hubo respuesta HTTP."""

    def __init__(self, message: str, *, status_code: int | None = None, detail: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


class AuthAPIError(ProvisionError):
    """Falló una llamada a auth_fastapi."""


class GateKeeperError(ProvisionError):
    """Falló una llamada a GateKeeper."""


class OrgOwnedByOtherProduct(AuthAPIError):
    """El slug ya existe y lo dio de alta otro producto (posible cliente compartido).

    No es un fallo: auth pide confirmación explícita para no pegar dos clientes
    homónimos al mismo registro de org. Muestra `org_name`/`created_by_product`
    al operador y, si confirma que es el mismo cliente, reintenta con
    `ensure_org(..., adopt_existing=True)`.
    """

    def __init__(self, message: str, *, status_code: int, detail: Any):
        super().__init__(message, status_code=status_code, detail=detail)
        info = detail if isinstance(detail, dict) else {}
        self.org_id: str | None = info.get("org_id")
        self.org_name: str | None = info.get("name")
        self.slug: str | None = info.get("slug")
        self.created_by_product: str | None = info.get("created_by_product")


@dataclass
class OrgResult:
    org_id: str
    name: str
    slug: str
    status: str  # "created" | "exists"
    created_by_product: str | None = None  # producto que la dio de alta

    def belongs_to_other_product(self, my_product: str) -> bool:
        """True si la org existía y la creó OTRO producto (cliente compartido).

        No es un error: es el mecanismo multi-producto. Sirve para que el panel
        pida confirmación ("esta org ya existe y la creó scriba, ¿es el mismo
        cliente?") en vez de adoptarla en silencio.
        """
        return (
            self.status == "exists"
            and self.created_by_product is not None
            and self.created_by_product != my_product
        )


@dataclass
class IdentityResult:
    user_id: int
    email: str
    role: str
    org_id: str
    status: str  # "created" | "added" | "already_member" | "role_updated"


@dataclass
class ApiKeyResult:
    key_id: int
    key_name: str
    org_id: str | None
    scopes: list[str] = field(default_factory=list)
    expires_at: str | None = None
    status: str = "created"  # "created" | "exists" | "rotated"
    secret: str | None = None  # solo en created/rotated — no se puede re-mostrar


class ProvisionClient:
    """Cliente de alta contra auth_fastapi + GateKeeper.

    auth_token / auth_token_provider: JWT del admin que ejecuta el alta (uno de los
    dos). El provider se llama en cada request — úsalo cuando el token viene de la
    sesión web (patrón habitual en los paneles de producto).
    gatekeeper_api_key: apikey de servicio del producto (scope admin:keys).
    """

    def __init__(
        self,
        *,
        auth_url: str,
        gatekeeper_url: str | None = None,
        auth_token: str | None = None,
        auth_token_provider: Callable[[], str] | None = None,
        gatekeeper_api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.auth_url = auth_url.rstrip("/")
        self.gatekeeper_url = gatekeeper_url.rstrip("/") if gatekeeper_url else None
        self._auth_token = auth_token
        self._auth_token_provider = auth_token_provider
        self.gatekeeper_api_key = gatekeeper_api_key
        self.timeout = timeout

    # ---------------------------------------------------------------- internals

    def _token(self) -> str:
        if self._auth_token_provider is not None:
            token = self._auth_token_provider()
            if not token:
                raise AuthAPIError("auth_token_provider devolvió un token vacío")
            return token
        if not self._auth_token:
            raise AuthAPIError("Falta auth_token o auth_token_provider")
        return self._auth_token

    def _request(
        self,
        method: str,
        url: str,
        *,
        token: str,
        body: dict | None = None,
        error_cls: type[ProvisionError],
    ) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "User-Agent": USER_AGENT,
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                payload = json.loads(raw) if raw else None
                return resp.status, payload
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                parsed = json.loads(raw) if raw else None
            except ValueError:
                parsed = raw.decode(errors="replace") if raw else None
            detail = parsed.get("detail", parsed) if isinstance(parsed, dict) else parsed
            raise error_cls(
                f"{method} {url} → HTTP {e.code}: {detail}",
                status_code=e.code,
                detail=detail,
            ) from e
        except urllib.error.URLError as e:
            raise error_cls(f"{method} {url} → sin respuesta: {e.reason}") from e
        except ValueError as e:  # JSON inválido en respuesta OK
            raise error_cls(f"{method} {url} → respuesta no es JSON: {e}") from e

    def _auth_request(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        return self._request(
            method,
            f"{self.auth_url}{path}",
            token=self._token(),
            body=body,
            error_cls=AuthAPIError,
        )

    def _gk_request(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        if not self.gatekeeper_url:
            raise GateKeeperError("Falta gatekeeper_url")
        if not self.gatekeeper_api_key:
            raise GateKeeperError("Falta gatekeeper_api_key")
        return self._request(
            method,
            f"{self.gatekeeper_url}{path}",
            token=self.gatekeeper_api_key,
            body=body,
            error_cls=GateKeeperError,
        )

    # ------------------------------------------------------------------- auth

    def ensure_org(
        self,
        name: str,
        slug: str,
        *,
        description: str | None = None,
        adopt_existing: bool = False,
    ) -> OrgResult:
        """Crea la org o devuelve la existente. Idempotente por slug.

        El slug identifica al CLIENTE, no a tu producto (`effixai`, `risingup`).
        Reintentar tu propia alta siempre es seguro (200).

        Si el slug existe y lo dio de alta OTRO producto —y tú aún no tienes
        miembros ahí— lanza `OrgOwnedByOtherProduct` en vez de adoptarla en
        silencio (protege contra clientes homónimos). Muestra los datos de la
        excepción al operador y, si confirma que es el mismo cliente, repite
        con `adopt_existing=True`. Basta una vez: al tener miembros con tu
        prefijo ya eres co-dueño.
        """
        body: dict[str, Any] = {"name": name, "slug": slug}
        if description is not None:
            body["description"] = description
        if adopt_existing:
            body["adopt_existing"] = True
        try:
            status_code, data = self._auth_request("POST", "/api/v1/admin/orgs", body)
        except AuthAPIError as e:
            if e.status_code == 409 and isinstance(e.detail, dict) and (
                e.detail.get("error") == "org_owned_by_other_product"
            ):
                raise OrgOwnedByOtherProduct(
                    str(e), status_code=e.status_code, detail=e.detail
                ) from e
            raise
        if not isinstance(data, dict) or "id" not in data:
            raise AuthAPIError("Respuesta inesperada de /admin/orgs", status_code=status_code, detail=data)
        return OrgResult(
            org_id=str(data["id"]),
            name=data.get("name", name),
            slug=data.get("slug", slug),
            status="created" if status_code == 201 else "exists",
            created_by_product=data.get("created_by_product"),
        )

    def ensure_identity(
        self,
        email: str,
        *,
        role: str,
        org_id: str,
        first_name: str = "",
        last_name: str = "",
        send_email: bool = True,
        product_name: str | None = None,
        accept_url: str | None = None,
    ) -> IdentityResult:
        """Asegura que el email exista en auth y sea miembro de la org con ese rol.

        Idempotente: nunca da 409. `status` dice qué pasó (created | added |
        already_member | role_updated). Con status="created" el usuario aún no
        existe hasta que acepte la invitación — `user_id` viene 0.
        """
        body: dict[str, Any] = {
            "email": email,
            "role": role,
            "org_id": org_id,
            "first_name": first_name,
            "last_name": last_name,
            "send_email": send_email,
        }
        if product_name is not None:
            body["product_name"] = product_name
        if accept_url is not None:
            body["accept_url"] = accept_url

        _, data = self._auth_request("POST", "/api/v1/admin/members", body)
        if not isinstance(data, dict) or "status" not in data:
            raise AuthAPIError("Respuesta inesperada de /admin/members", detail=data)
        return IdentityResult(
            user_id=data.get("user_id", 0),
            email=data.get("email", email),
            role=data.get("role", role),
            org_id=str(data.get("org_id", org_id)),
            status=data["status"],
        )

    def get_user_by_email(self, email: str) -> dict | None:
        """Devuelve el usuario con sus membresías, o None si no existe."""
        quoted = urllib.parse.quote(email, safe="")
        try:
            _, data = self._auth_request("GET", f"/api/v1/admin/users/by-email?email={quoted}")
        except AuthAPIError as e:
            if e.status_code == 404:
                return None
            raise
        return data

    # ------------------------------------------------------------- gatekeeper

    def ensure_apikey(
        self,
        org_id: str | None,
        key_name: str,
        *,
        scopes: list[str],
        client_name: str | None = None,
        rate_limit_per_minute: int = 60,
        expires_days: int = DEFAULT_EXPIRES_DAYS,
        description: str | None = None,
        metadata: dict | None = None,
    ) -> ApiKeyResult:
        """Crea la apikey o devuelve la existente para (org_id, key_name).

        `secret` solo viene cuando status="created" — el secreto no se puede
        re-mostrar (GateKeeper solo guarda el hash). Si status="exists" y el
        producto perdió el secreto, usa `rotate_apikey`.
        `expires_days=-1` = sin expiración.
        """
        body: dict[str, Any] = {
            "key_name": key_name,
            "client_name": client_name or key_name,
            "scopes": scopes,
            "rate_limit_per_minute": rate_limit_per_minute,
            "expires_days": expires_days,
        }
        if org_id is not None:
            body["org_id"] = org_id
        if description is not None:
            body["description"] = description
        if metadata is not None:
            body["metadata"] = metadata

        status_code, data = self._gk_request("POST", "/api/keys", body)
        return self._parse_apikey(
            data,
            fallback_status="created" if status_code == 201 else "exists",
            fallback_name=key_name,
            fallback_org=org_id,
        )

    def rotate_apikey(self, key_id: int) -> ApiKeyResult:
        """Genera un secreto nuevo; el anterior sigue válido 24h (gracia)."""
        _, data = self._gk_request("POST", f"/api/keys/{key_id}/rotate")
        return self._parse_apikey(data, fallback_status="rotated", fallback_name="", fallback_org=None)

    @staticmethod
    def _parse_apikey(
        data: Any,
        *,
        fallback_status: str,
        fallback_name: str,
        fallback_org: str | None,
    ) -> ApiKeyResult:
        if not isinstance(data, dict):
            raise GateKeeperError("Respuesta inesperada de GateKeeper", detail=data)
        # GateKeeper responde {"status": ..., "api_key": {...}}
        key = data.get("api_key") if isinstance(data.get("api_key"), dict) else data
        key_id = key.get("id", key.get("key_id"))
        if key_id is None:
            raise GateKeeperError("Respuesta de GateKeeper sin id de key", detail=data)
        return ApiKeyResult(
            key_id=int(key_id),
            key_name=key.get("key_name", fallback_name),
            org_id=key.get("org_id", fallback_org),
            scopes=key.get("scopes") or [],
            expires_at=key.get("expires_at"),
            status=data.get("status", fallback_status),
            secret=key.get("key"),
        )
