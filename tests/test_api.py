"""Tests for the UniFi Connect Display API client."""
from __future__ import annotations

import base64
import json
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.unifi_display.api import (
    AuthenticationError,
    CannotConnectError,
    UniFiDisplayAPI,
    _parse_devices_response,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jwt(csrf_token: str = "test-csrf-token") -> str:
    """Build a minimal JWT whose payload contains ``csrfToken``."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
    payload_data = {"csrfToken": csrf_token, "unique_id": "user-1"}
    payload = (
        base64.urlsafe_b64encode(json.dumps(payload_data).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.signature"


def _mock_response(status: int = 200, json_data=None, set_cookie: str | None = None):
    """Create a mock aiohttp response."""
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data if json_data is not None else {})
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    if set_cookie is not None:
        resp.headers = MagicMock()
        resp.headers.getall = MagicMock(return_value=[set_cookie])
    else:
        resp.headers = MagicMock()
        resp.headers.getall = MagicMock(return_value=[])
    return resp


# ---------------------------------------------------------------------------
# _extract_csrf_from_jwt
# ---------------------------------------------------------------------------

class TestExtractCsrfFromJwt:
    def test_extracts_csrf_from_valid_jwt(self):
        jwt = _make_jwt("my-csrf-token")
        result = UniFiDisplayAPI._extract_csrf_from_jwt(jwt)
        assert result == "my-csrf-token"

    def test_returns_none_for_invalid_jwt(self):
        result = UniFiDisplayAPI._extract_csrf_from_jwt("not.a.jwt")
        assert result is None

    def test_returns_none_for_empty_string(self):
        result = UniFiDisplayAPI._extract_csrf_from_jwt("")
        assert result is None

    def test_returns_none_when_csrf_token_absent(self):
        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        payload = (
            base64.urlsafe_b64encode(b'{"sub":"user"}').rstrip(b"=").decode()
        )
        jwt = f"{header}.{payload}.sig"
        result = UniFiDisplayAPI._extract_csrf_from_jwt(jwt)
        assert result is None

    def test_handles_padding_variants(self):
        """JWT payload lengths that require different amounts of base64 padding."""
        for extra in range(4):
            token = "x" * (10 + extra)
            jwt = _make_jwt(csrf_token=token)
            assert UniFiDisplayAPI._extract_csrf_from_jwt(jwt) == token


# ---------------------------------------------------------------------------
# _extract_token_from_set_cookie_headers
# ---------------------------------------------------------------------------

class TestExtractTokenFromSetCookieHeaders:
    def test_extracts_token_from_plain_set_cookie(self):
        headers = {"Set-Cookie": "TOKEN=abc123; path=/; httponly"}
        result = UniFiDisplayAPI._extract_token_from_set_cookie_headers(headers)
        assert result == "abc123"

    def test_extracts_token_with_partitioned_attribute(self):
        jwt = _make_jwt("csrf-xyz")
        set_cookie = f"TOKEN={jwt}; path=/; samesite=none; secure; httponly; partitioned"
        headers = {"Set-Cookie": set_cookie}
        result = UniFiDisplayAPI._extract_token_from_set_cookie_headers(headers)
        assert result == jwt

    def test_returns_none_when_no_token_cookie(self):
        headers = {"Set-Cookie": "SESSION=xyz; path=/"}
        result = UniFiDisplayAPI._extract_token_from_set_cookie_headers(headers)
        assert result is None

    def test_returns_none_when_no_set_cookie_header(self):
        headers = {"Content-Type": "application/json"}
        result = UniFiDisplayAPI._extract_token_from_set_cookie_headers(headers)
        assert result is None

    def test_uses_getall_for_multidict(self):
        """Supports multi-value headers (e.g. aiohttp CIMultiDictProxy)."""
        jwt = _make_jwt("csrf-multi")
        mock_headers = MagicMock()
        mock_headers.getall = MagicMock(
            return_value=[
                "SESSION=other; path=/",
                f"TOKEN={jwt}; path=/; partitioned",
            ]
        )
        result = UniFiDisplayAPI._extract_token_from_set_cookie_headers(mock_headers)
        assert result == jwt

    def test_returns_none_on_exception(self):
        headers = MagicMock()
        headers.getall = MagicMock(side_effect=RuntimeError("fail"))
        del headers.__contains__  # ensure plain-dict fallback also fails
        result = UniFiDisplayAPI._extract_token_from_set_cookie_headers(headers)
        assert result is None


# ---------------------------------------------------------------------------
# Host normalisation
# ---------------------------------------------------------------------------

class TestHostNormalisation:
    def test_prepends_https_when_no_scheme(self):
        api = UniFiDisplayAPI("192.168.1.1", "u", "p", "dev-id")
        assert api._host == "https://192.168.1.1"

    def test_preserves_https_scheme(self):
        api = UniFiDisplayAPI("https://192.168.1.1", "u", "p", "dev-id")
        assert api._host == "https://192.168.1.1"

    def test_preserves_http_scheme(self):
        api = UniFiDisplayAPI("http://192.168.1.1", "u", "p", "dev-id")
        assert api._host == "http://192.168.1.1"

    def test_strips_trailing_slash(self):
        api = UniFiDisplayAPI("192.168.1.1/", "u", "p", "dev-id")
        assert api._host == "https://192.168.1.1"

    def test_raises_value_error_for_invalid_host(self):
        with pytest.raises(ValueError):
            UniFiDisplayAPI("", "u", "p", "dev-id")


# ---------------------------------------------------------------------------
# authenticate
# ---------------------------------------------------------------------------

class TestAuthenticate:
    @pytest.fixture
    def api(self):
        return UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")

    def _mock_session(
        self,
        status: int,
        body: dict,
        jwt: str | None = None,
        set_cookie: str | None = None,
    ):
        """Build a mock session for authenticate() calls.

        Args:
            jwt: If set, the cookie jar returns a TOKEN cookie with this value.
            set_cookie: If set, the response ``Set-Cookie`` header contains
                this raw cookie string (simulates the ``Partitioned`` scenario).
        """
        resp = _mock_response(status=status, json_data=body, set_cookie=set_cookie)
        session = MagicMock()
        session.closed = False
        session.post = MagicMock(return_value=resp)

        cookie_jar = MagicMock()
        if jwt is not None:
            token_cookie = MagicMock()
            token_cookie.value = jwt
            cookie_jar.filter_cookies = MagicMock(
                return_value={"TOKEN": token_cookie}
            )
        else:
            cookie_jar.filter_cookies = MagicMock(return_value={})
        session.cookie_jar = cookie_jar
        return session

    @pytest.mark.asyncio
    async def test_successful_auth_sets_csrf_token(self, api):
        jwt = _make_jwt("csrf-abc")
        session = self._mock_session(
            status=200, body={"unique_id": "u1"}, jwt=jwt
        )
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.authenticate()
        assert api._csrf_token == "csrf-abc"

    @pytest.mark.asyncio
    async def test_partitioned_cookie_sets_csrf_token(self, api):
        """TOKEN in Set-Cookie with Partitioned attribute is parsed correctly."""
        jwt = _make_jwt("csrf-partitioned")
        set_cookie = (
            f"TOKEN={jwt}; path=/; samesite=none; secure; httponly; partitioned"
        )
        # Cookie jar returns nothing (simulates Partitioned rejection).
        session = self._mock_session(
            status=200, body={"unique_id": "u1"}, set_cookie=set_cookie
        )
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.authenticate()
        assert api._csrf_token == "csrf-partitioned"
        assert api._token == jwt

    @pytest.mark.asyncio
    async def test_set_cookie_header_takes_priority_over_jar(self, api):
        """When both Set-Cookie header and cookie jar provide TOKEN, header wins."""
        jwt_header = _make_jwt("csrf-from-header")
        jwt_jar = _make_jwt("csrf-from-jar")
        set_cookie = f"TOKEN={jwt_header}; path=/; partitioned"
        session = self._mock_session(
            status=200,
            body={"unique_id": "u1"},
            jwt=jwt_jar,
            set_cookie=set_cookie,
        )
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.authenticate()
        assert api._csrf_token == "csrf-from-header"
        assert api._token == jwt_header

    @pytest.mark.asyncio
    async def test_raises_auth_error_on_non_200(self, api):
        session = self._mock_session(status=401, body={"error": "Unauthorized"})
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(AuthenticationError):
                await api.authenticate()

    @pytest.mark.asyncio
    async def test_raises_auth_error_on_unexpected_body(self, api):
        session = self._mock_session(
            status=200, body={"unexpected_key": "value"}
        )
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(AuthenticationError):
                await api.authenticate()

    @pytest.mark.asyncio
    async def test_raises_cannot_connect_on_client_error(self, api):
        import aiohttp

        resp = MagicMock()
        resp.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("conn failed"))
        resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.closed = False
        session.post = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(CannotConnectError):
                await api.authenticate()


# ---------------------------------------------------------------------------
# send_action
# ---------------------------------------------------------------------------

class TestSendAction:
    @pytest.fixture
    def api(self):
        api = UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")
        api._csrf_token = "existing-csrf"
        return api

    def _patched_session(self, status: int):
        resp = _mock_response(status=status)
        session = MagicMock()
        session.closed = False
        session.patch = MagicMock(return_value=resp)
        return session

    @pytest.mark.asyncio
    async def test_returns_true_on_200(self, api):
        session = self._patched_session(200)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.send_action("display_on")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_true_on_204(self, api):
        session = self._patched_session(204)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.send_action("display_off")
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_500(self, api):
        session = self._patched_session(500)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.send_action("reboot")
        assert result is False

    @pytest.mark.asyncio
    async def test_passes_args_in_body(self, api):
        """Verify the PATCH body includes the provided args."""
        captured_body = {}

        resp = MagicMock()
        resp.status = 200
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.closed = False

        def fake_patch(url, json=None, headers=None):
            captured_body.update(json or {})
            return resp

        session.patch = fake_patch

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.send_action("brightness", {"level": 80})

        assert captured_body["name"] == "brightness"
        assert captured_body["args"] == {"level": 80}

    @pytest.mark.asyncio
    async def test_returns_false_on_client_error(self, api):
        import aiohttp

        session = MagicMock()
        session.closed = False

        resp = MagicMock()
        resp.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("err"))
        resp.__aexit__ = AsyncMock(return_value=False)
        session.patch = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.send_action("display_on")
        assert result is False

    @pytest.mark.asyncio
    async def test_reauths_on_403_and_retries(self, api):
        """A 403 response triggers re-authentication and a second PATCH attempt."""
        resp_403 = _mock_response(status=403)
        resp_200 = _mock_response(status=200)

        session = MagicMock()
        session.closed = False
        session.patch = MagicMock(side_effect=[resp_403, resp_200])

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with patch.object(api, "authenticate", AsyncMock()):
                result = await api.send_action("display_on")

        assert result is True


# ---------------------------------------------------------------------------
# get_devices
# ---------------------------------------------------------------------------

class TestGetDevices:
    @pytest.fixture
    def api(self):
        api = UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")
        api._csrf_token = "existing-csrf"
        return api

    @pytest.mark.asyncio
    async def test_returns_device_list(self, api):
        devices = [{"id": "d1", "name": "Living Room Display"}]
        resp = _mock_response(status=200, json_data=devices)
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_devices()
        assert result == devices

    @pytest.mark.asyncio
    async def test_returns_empty_list_on_non_list_response(self, api):
        resp = _mock_response(status=200, json_data={"error": "oops"})
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_devices()
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_device_list_from_wrapper_response(self, api):
        devices = [{"id": "d1", "name": "Living Room Display"}]
        wrapper = {"err": None, "type": "collection", "data": devices, "offset": 0, "limit": 0}
        resp = _mock_response(status=200, json_data=wrapper)
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_devices()
        assert result == devices


# ---------------------------------------------------------------------------
# _parse_devices_response
# ---------------------------------------------------------------------------

class TestParseDevicesResponse:
    def test_bare_list(self):
        devices = [{"id": "d1"}]
        assert _parse_devices_response(devices) == devices

    def test_wrapper_dict(self):
        devices = [{"id": "d1"}, {"id": "d2"}]
        wrapper = {"err": None, "type": "collection", "data": devices, "offset": 0, "limit": 0}
        assert _parse_devices_response(wrapper) == devices

    def test_empty_wrapper_data(self):
        wrapper = {"err": None, "type": "collection", "data": [], "offset": 0, "limit": 0}
        assert _parse_devices_response(wrapper) == []

    def test_unexpected_dict_returns_empty(self):
        assert _parse_devices_response({"error": "oops"}) == []

    def test_none_returns_empty(self):
        assert _parse_devices_response(None) == []

    def test_string_returns_empty(self):
        assert _parse_devices_response("unexpected") == []


# ---------------------------------------------------------------------------
# _parse_device_status
# ---------------------------------------------------------------------------

class TestParseDeviceStatus:
    def test_bare_dict_returned_unchanged(self):
        data = {"brightness": 80, "volume": 50, "state": "on"}
        result = UniFiDisplayAPI._parse_device_status(data)
        assert result["brightness"] == 80
        assert result["volume"] == 50
        assert result["state"] == "on"

    def test_wrapper_dict_is_unwrapped(self):
        inner = {"brightness": 80, "volume": 50}
        data = {"data": inner, "err": None}
        result = UniFiDisplayAPI._parse_device_status(data)
        assert result["brightness"] == 80
        assert result["volume"] == 50

    def test_camel_case_display_state_mapped(self):
        data = {"displayState": "on", "brightness": 80}
        result = UniFiDisplayAPI._parse_device_status(data)
        assert result["state"] == "on"

    def test_camel_case_ip_address_mapped(self):
        data = {"ipAddress": "192.168.1.50"}
        result = UniFiDisplayAPI._parse_device_status(data)
        assert result["ip"] == "192.168.1.50"

    def test_camel_case_link_quality_mapped(self):
        data = {"linkQuality": 95}
        result = UniFiDisplayAPI._parse_device_status(data)
        assert result["link_quality"] == 95

    def test_existing_snake_case_key_not_overwritten(self):
        """If both camelCase and snake_case keys exist, the existing snake_case wins."""
        data = {"state": "off", "displayState": "on"}
        result = UniFiDisplayAPI._parse_device_status(data)
        assert result["state"] == "off"

    def test_non_dict_returns_empty(self):
        assert UniFiDisplayAPI._parse_device_status([]) == {}
        assert UniFiDisplayAPI._parse_device_status(None) == {}
        assert UniFiDisplayAPI._parse_device_status("string") == {}


# ---------------------------------------------------------------------------
# get_device_status
# ---------------------------------------------------------------------------

class TestGetDeviceStatus:
    @pytest.fixture
    def api(self):
        api = UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")
        api._csrf_token = "existing-csrf"
        return api

    @pytest.mark.asyncio
    async def test_returns_parsed_device_status(self, api):
        device_data = {"brightness": 80, "volume": 50, "displayState": "on"}
        resp = _mock_response(status=200, json_data=device_data)
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_device_status()
        assert result["brightness"] == 80
        assert result["state"] == "on"

    @pytest.mark.asyncio
    async def test_reauths_on_401(self, api):
        resp_401 = _mock_response(status=401)
        resp_200 = _mock_response(status=200, json_data={"brightness": 70})

        session = MagicMock()
        session.closed = False
        session.get = MagicMock(side_effect=[resp_401, resp_200])

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with patch.object(api, "authenticate", AsyncMock()):
                result = await api.get_device_status()

        assert result["brightness"] == 70

    @pytest.mark.asyncio
    async def test_reauths_on_403(self, api):
        resp_403 = _mock_response(status=403)
        resp_200 = _mock_response(status=200, json_data={"brightness": 60})

        session = MagicMock()
        session.closed = False
        session.get = MagicMock(side_effect=[resp_403, resp_200])

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with patch.object(api, "authenticate", AsyncMock()):
                result = await api.get_device_status()

        assert result["brightness"] == 60

    @pytest.mark.asyncio
    async def test_raises_cannot_connect_on_client_error(self, api):
        import aiohttp

        resp = MagicMock()
        resp.__aenter__ = AsyncMock(side_effect=aiohttp.ClientError("err"))
        resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(CannotConnectError):
                await api.get_device_status()



# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------

class TestClose:
    @pytest.mark.asyncio
    async def test_closes_open_session(self):
        api = UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")
        mock_session = AsyncMock()
        mock_session.closed = False
        api._session = mock_session
        await api.close()
        mock_session.close.assert_called_once()
        assert api._session is None

    @pytest.mark.asyncio
    async def test_noop_when_session_is_none(self):
        api = UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")
        # Should not raise
        await api.close()
