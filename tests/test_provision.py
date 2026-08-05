import io
import json
import urllib.error
import urllib.request

import pytest

from lw_auth.provision import (
    AuthAPIError,
    GateKeeperError,
    OrgOwnedByOtherProduct,
    ProvisionClient,
)

AUTH = "https://auth.test"
GK = "https://gk.test"


class _FakeResponse(io.BytesIO):
    """Mimics the context-manager response urlopen returns."""

    def __init__(self, payload, status=200):
        super().__init__(json.dumps(payload).encode() if payload is not None else b"")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
        return False


def _patch(monkeypatch, handler):
    """handler(req) -> _FakeResponse | raises. Records calls in `calls`."""
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req)
        return handler(req)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return calls


def _http_error(code, body):
    return urllib.error.HTTPError(
        url="x", code=code, msg="err", hdrs=None, fp=io.BytesIO(json.dumps(body).encode())
    )


def _client(**kwargs):
    defaults = dict(
        auth_url=AUTH,
        gatekeeper_url=GK,
        auth_token="jwt-token",
        gatekeeper_api_key="gk-service-key",
    )
    defaults.update(kwargs)
    return ProvisionClient(**defaults)


class TestEnsureOrg:
    def test_created_201(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "uuid-1", "name": "Acme", "slug": "sofom-acme"}, status=201
        ))
        result = _client().ensure_org("Acme", "sofom-acme")
        assert result.status == "created"
        assert result.org_id == "uuid-1"

    def test_exists_200(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "uuid-1", "name": "Acme", "slug": "sofom-acme"}, status=200
        ))
        result = _client().ensure_org("Acme", "sofom-acme")
        assert result.status == "exists"
        assert result.org_id == "uuid-1"

    def test_created_by_product_expuesto(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "uuid-1", "name": "EffixAI", "slug": "effixai",
             "created_by_product": "scriba"}, status=200
        ))
        result = _client().ensure_org("EffixAI", "effixai")
        assert result.created_by_product == "scriba"
        # Cliente compartido: la creó otro producto
        assert result.belongs_to_other_product("legal") is True
        assert result.belongs_to_other_product("scriba") is False

    def test_org_propia_no_marca_otro_producto(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "uuid-1", "name": "Rising", "slug": "risingup",
             "created_by_product": "legal"}, status=201
        ))
        result = _client().ensure_org("Rising", "risingup")
        assert result.belongs_to_other_product("legal") is False

    def test_error_de_auth_se_propaga(self, monkeypatch):
        def handler(req):
            raise _http_error(403, {"detail": "Missing permission: orgs.create"})

        _patch(monkeypatch, handler)
        with pytest.raises(AuthAPIError) as exc:
            _client().ensure_org("Acme", "acme")
        assert exc.value.status_code == 403

    def test_sends_bearer_token_and_ua(self, monkeypatch):
        calls = _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "u", "name": "n", "slug": "sofom-acme"}, status=201
        ))
        _client().ensure_org("n", "sofom-acme")
        req = calls[0]
        assert req.get_header("Authorization") == "Bearer jwt-token"
        assert req.get_header("User-agent").startswith("lw-auth/")
        assert req.full_url == f"{AUTH}/api/v1/admin/orgs"


class TestEnsureIdentity:
    @pytest.mark.parametrize(
        "status", ["created", "added", "already_member", "role_updated"]
    )
    def test_status_passthrough(self, monkeypatch, status):
        _patch(monkeypatch, lambda req: _FakeResponse({
            "user_id": 42, "email": "a@b.mx", "role": "legal_admin",
            "org_id": "uuid-1", "status": status,
        }))
        result = _client().ensure_identity("a@b.mx", role="legal_admin", org_id="uuid-1")
        assert result.status == status
        assert result.user_id == 42

    def test_optional_branding_fields_sent(self, monkeypatch):
        calls = _patch(monkeypatch, lambda req: _FakeResponse({
            "user_id": 0, "email": "a@b.mx", "role": "legal_admin",
            "org_id": "uuid-1", "status": "created",
        }))
        _client().ensure_identity(
            "a@b.mx", role="legal_admin", org_id="uuid-1",
            product_name="CGA Legal", accept_url="https://app.cga-law.com/aceptar",
        )
        body = json.loads(calls[0].data)
        assert body["product_name"] == "CGA Legal"
        assert body["accept_url"] == "https://app.cga-law.com/aceptar"

    def test_unexpected_shape_raises(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse({"algo": "raro"}))
        with pytest.raises(AuthAPIError):
            _client().ensure_identity("a@b.mx", role="r", org_id="o")


class TestGetUserByEmail:
    def test_found(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse({"user_id": 1, "memberships": []}))
        assert _client().get_user_by_email("a@b.mx")["user_id"] == 1

    def test_not_found_returns_none(self, monkeypatch):
        def handler(req):
            raise _http_error(404, {"detail": "User not found"})

        _patch(monkeypatch, handler)
        assert _client().get_user_by_email("nadie@b.mx") is None

    def test_other_error_raises(self, monkeypatch):
        def handler(req):
            raise _http_error(500, {"detail": "boom"})

        _patch(monkeypatch, handler)
        with pytest.raises(AuthAPIError):
            _client().get_user_by_email("a@b.mx")

    def test_email_is_url_encoded(self, monkeypatch):
        calls = _patch(monkeypatch, lambda req: _FakeResponse({"user_id": 1}))
        _client().get_user_by_email("a+x@b.mx")
        assert "a%2Bx%40b.mx" in calls[0].full_url


class TestEnsureApikey:
    def test_created_has_secret(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse({
            "status": "created",
            "api_key": {"id": 7, "key_name": "legal-acme-api", "org_id": "uuid-1",
                        "scopes": ["legalops:read"], "key": "sk_secret"},
        }, status=201))
        result = _client().ensure_apikey("uuid-1", "legal-acme-api", scopes=["legalops:read"])
        assert result.status == "created"
        assert result.secret == "sk_secret"
        assert result.key_id == 7

    def test_exists_has_no_secret(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse({
            "status": "exists",
            "api_key": {"id": 7, "key_name": "legal-acme-api", "org_id": "uuid-1",
                        "scopes": ["legalops:read"]},
        }, status=200))
        result = _client().ensure_apikey("uuid-1", "legal-acme-api", scopes=["legalops:read"])
        assert result.status == "exists"
        assert result.secret is None

    def test_uses_gatekeeper_key_not_jwt(self, monkeypatch):
        calls = _patch(monkeypatch, lambda req: _FakeResponse({
            "status": "created", "api_key": {"id": 1, "key": "s"},
        }, status=201))
        _client().ensure_apikey("uuid-1", "k", scopes=["a:b"])
        assert calls[0].get_header("Authorization") == "Bearer gk-service-key"
        assert calls[0].full_url == f"{GK}/api/keys"

    def test_defaults_expires_365(self, monkeypatch):
        calls = _patch(monkeypatch, lambda req: _FakeResponse({
            "status": "created", "api_key": {"id": 1, "key": "s"},
        }, status=201))
        _client().ensure_apikey("uuid-1", "k", scopes=["a:b"])
        assert json.loads(calls[0].data)["expires_days"] == 365

    def test_scope_rejected_by_ceiling(self, monkeypatch):
        def handler(req):
            raise _http_error(403, {"error": "Scope no permitido para esta application"})

        _patch(monkeypatch, handler)
        with pytest.raises(GateKeeperError) as exc:
            _client().ensure_apikey("uuid-1", "k", scopes=["admin:keys"])
        assert exc.value.status_code == 403

    def test_missing_gatekeeper_config_raises(self, monkeypatch):
        client = ProvisionClient(auth_url=AUTH, auth_token="t")
        with pytest.raises(GateKeeperError):
            client.ensure_apikey("uuid-1", "k", scopes=["a:b"])


class TestRotate:
    def test_rotate_returns_new_secret(self, monkeypatch):
        _patch(monkeypatch, lambda req: _FakeResponse({
            "status": "rotated",
            "api_key": {"id": 8, "key_name": "legal-acme-api", "key": "sk_new"},
            "previous_key_expires_at": "2026-08-06T00:00:00Z",
        }, status=201))
        result = _client().rotate_apikey(7)
        assert result.status == "rotated"
        assert result.secret == "sk_new"


class TestTokenProvider:
    def test_provider_called_per_request(self, monkeypatch):
        tokens = iter(["tok-1", "tok-2"])
        calls = _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "u", "name": "n", "slug": "risingup"}, status=201
        ))
        client = _client(auth_token=None, auth_token_provider=lambda: next(tokens))
        client.ensure_org("n", "risingup")
        client.ensure_org("n", "risingup")
        assert calls[0].get_header("Authorization") == "Bearer tok-1"
        assert calls[1].get_header("Authorization") == "Bearer tok-2"

    def test_empty_token_raises(self):
        client = _client(auth_token=None, auth_token_provider=lambda: "")
        with pytest.raises(AuthAPIError):
            client.ensure_org("n", "risingup")

    def test_no_token_at_all_raises(self):
        client = ProvisionClient(auth_url=AUTH)
        with pytest.raises(AuthAPIError):
            client.ensure_org("n", "risingup")


class TestNetworkErrors:
    def test_urlerror_wrapped(self, monkeypatch):
        def handler(req):
            raise urllib.error.URLError("timed out")

        _patch(monkeypatch, handler)
        with pytest.raises(AuthAPIError) as exc:
            _client().ensure_org("n", "risingup")
        assert exc.value.status_code is None

    def test_bad_json_wrapped(self, monkeypatch):
        class BadBody(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def handler(req):
            r = BadBody(b"<html>not json</html>")
            r.status = 200
            return r

        _patch(monkeypatch, handler)
        with pytest.raises(AuthAPIError):
            _client().ensure_org("n", "risingup")


class TestAdopcionExplicita:
    """409 org_owned_by_other_product → excepción tipada; adopt_existing la resuelve."""

    _CONFLICTO = {
        "error": "org_owned_by_other_product",
        "message": "El slug ya existe y pertenece a otro producto.",
        "org_id": "uuid-9",
        "name": "EffixAI",
        "slug": "effixai",
        "created_by_product": "scriba",
    }

    def test_409_lanza_excepcion_con_datos(self, monkeypatch):
        def handler(req):
            raise _http_error(409, {"detail": self._CONFLICTO})

        _patch(monkeypatch, handler)
        with pytest.raises(OrgOwnedByOtherProduct) as exc:
            _client().ensure_org("EffixAI", "effixai")
        e = exc.value
        assert e.org_id == "uuid-9"
        assert e.org_name == "EffixAI"
        assert e.created_by_product == "scriba"
        # Sigue siendo un AuthAPIError: quien no distinga, lo captura igual
        assert isinstance(e, AuthAPIError)

    def test_adopt_existing_va_en_el_body(self, monkeypatch):
        calls = _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "uuid-9", "name": "EffixAI", "slug": "effixai",
             "created_by_product": "scriba"}, status=200
        ))
        result = _client().ensure_org("EffixAI", "effixai", adopt_existing=True)
        assert json.loads(calls[0].data)["adopt_existing"] is True
        assert result.status == "exists"

    def test_sin_flag_no_manda_el_campo(self, monkeypatch):
        calls = _patch(monkeypatch, lambda req: _FakeResponse(
            {"id": "u", "name": "n", "slug": "risingup"}, status=201
        ))
        _client().ensure_org("n", "risingup")
        assert "adopt_existing" not in json.loads(calls[0].data)

    def test_otro_409_no_se_confunde(self, monkeypatch):
        """Un 409 distinto sigue siendo AuthAPIError genérico."""
        def handler(req):
            raise _http_error(409, {"detail": "otra cosa"})

        _patch(monkeypatch, handler)
        with pytest.raises(AuthAPIError) as exc:
            _client().ensure_org("n", "otra")
        assert not isinstance(exc.value, OrgOwnedByOtherProduct)
