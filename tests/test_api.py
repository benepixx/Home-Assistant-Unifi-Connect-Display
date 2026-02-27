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
from custom_components.unifi_display.switch import STATE_KEY_MAP


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


def _mock_response(status: int = 200, json_data=None, set_cookie: str | None = None, csrf_header: str | None = None):
    """Create a mock aiohttp response."""
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data if json_data is not None else {})
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    resp.headers = MagicMock()
    if set_cookie is not None:
        resp.headers.getall = MagicMock(return_value=[set_cookie])
    else:
        resp.headers.getall = MagicMock(return_value=[])
    # Configure .get() to return csrf_header for CSRF header names, None otherwise.
    def _headers_get(key, default=None):
        if key in ("X-Updated-Csrf-Token", "X-CSRF-Token"):
            return csrf_header
        return default
    resp.headers.get = MagicMock(side_effect=_headers_get)
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
        csrf_header: str | None = None,
    ):
        """Build a mock session for authenticate() calls.

        Args:
            jwt: If set, the cookie jar returns a TOKEN cookie with this value.
            set_cookie: If set, the response ``Set-Cookie`` header contains
                this raw cookie string (simulates the ``Partitioned`` scenario).
            csrf_header: If set, the response ``X-Updated-Csrf-Token`` header
                returns this value (simulates current controller behaviour).
        """
        resp = _mock_response(status=status, json_data=body, set_cookie=set_cookie, csrf_header=csrf_header)
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

    @pytest.mark.asyncio
    async def test_csrf_from_response_header_takes_priority(self, api):
        """X-Updated-Csrf-Token response header takes priority over JWT extraction."""
        jwt = _make_jwt("csrf-from-jwt")
        set_cookie = f"TOKEN={jwt}; path=/; partitioned"
        session = self._mock_session(
            status=200,
            body={"unique_id": "u1"},
            set_cookie=set_cookie,
            csrf_header="csrf-from-response-header",
        )
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.authenticate()
        assert api._csrf_token == "csrf-from-response-header"

    @pytest.mark.asyncio
    async def test_csrf_from_header_with_cookie_jar_fallback(self, api):
        """CSRF from response header is used even when token comes from cookie jar."""
        jwt = _make_jwt("csrf-from-jwt")
        session = self._mock_session(
            status=200,
            body={"unique_id": "u1"},
            jwt=jwt,
            csrf_header="csrf-header-value",
        )
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.authenticate()
        assert api._csrf_token == "csrf-header-value"


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

    @pytest.mark.asyncio
    async def test_uses_action_id_from_map(self, api):
        """When _action_id_map has the action, its UUID is used in the body."""
        known_uuid = "ea959362-c56f-4932-ab8b-0f512a93460c"
        api._action_id_map = {"display_off": known_uuid}
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
            await api.send_action("display_off")

        assert captured_body["id"] == known_uuid
        assert captured_body["name"] == "display_off"

    @pytest.mark.asyncio
    async def test_falls_back_to_random_uuid_when_action_not_in_map(self, api):
        """When action is not in _action_id_map, a UUID is still sent."""
        import re
        api._action_id_map = {}
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
            with patch.object(api, "get_devices", AsyncMock(return_value=[])):
                await api.send_action("display_on")

        uuid_re = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        assert uuid_re.match(captured_body["id"]), f"Expected UUID, got: {captured_body['id']}"

    @pytest.mark.asyncio
    async def test_fetches_devices_to_populate_action_id_map_when_empty(self, api):
        """send_action calls get_devices() to populate action UUID map when action is missing."""
        known_uuid = "06ad25d0-b087-46de-8e9b-7b18339e7238"
        api._action_id_map = {}
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

        async def fake_get_devices():
            api._action_id_map["display_on"] = known_uuid
            return []

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with patch.object(api, "get_devices", AsyncMock(side_effect=fake_get_devices)):
                await api.send_action("display_on")

        assert captured_body["id"] == known_uuid
        assert captured_body["name"] == "display_on"

    @pytest.mark.asyncio
    async def test_no_authorization_header_in_send_action(self, api):
        """send_action must NOT include an Authorization: Bearer header."""
        api._token = "my-token"
        captured_headers = {}

        resp = MagicMock()
        resp.status = 200
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.closed = False

        def fake_patch(url, json=None, headers=None):
            captured_headers.update(headers or {})
            return resp

        session.patch = fake_patch

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.send_action("display_on")

        assert "Authorization" not in captured_headers
        assert captured_headers.get("Cookie") == "TOKEN=my-token"
        assert "X-CSRF-Token" in captured_headers
        assert "Origin" in captured_headers

    @pytest.mark.asyncio
    async def test_reauth_retry_no_authorization_header(self, api):
        """After re-auth on 403, the retry PATCH should also omit Authorization."""
        api._token = "initial-token"
        resp_403 = _mock_response(status=403)
        resp_200 = _mock_response(status=200)

        captured_retry_headers = {}

        session = MagicMock()
        session.closed = False

        call_count = [0]
        original_patch = MagicMock(side_effect=[resp_403, resp_200])

        def fake_patch(url, json=None, headers=None):
            call_count[0] += 1
            if call_count[0] == 2:
                captured_retry_headers.update(headers or {})
            return original_patch(url, json=json, headers=headers)

        session.patch = fake_patch

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with patch.object(api, "authenticate", AsyncMock()):
                await api.send_action("display_on")

        assert "Authorization" not in captured_retry_headers

    @pytest.mark.asyncio
    async def test_marks_unsupported_action_on_400(self, api):
        """HTTP 400 'action not found' marks the action in _unsupported_actions."""
        resp = MagicMock()
        resp.status = 400
        resp.text = AsyncMock(
            return_value='{"err":{"msg":"invalid action: action not found"}}'
        )
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.closed = False
        session.patch = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.send_action("enable_auto_rotate")

        assert result is False
        assert "enable_auto_rotate" in api._unsupported_actions

    @pytest.mark.asyncio
    async def test_non_json_response_body_logged_without_crash(self, api):
        """A non-JSON (plain text) response body on failure should not cause a crash."""
        resp = MagicMock()
        resp.status = 500
        resp.text = AsyncMock(return_value="Internal Server Error")
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.closed = False
        session.patch = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.send_action("display_on")

        assert result is False  # 500 → False, no crash

    def test_is_action_supported_returns_true_by_default(self, api):
        """Actions not yet tested are considered supported."""
        assert api.is_action_supported("display_on") is True

    def test_is_action_supported_returns_false_after_rejection(self, api):
        """Actions added to _unsupported_actions are reported as unsupported."""
        api._unsupported_actions.add("enable_auto_rotate")
        assert api.is_action_supported("enable_auto_rotate") is False

    @pytest.mark.asyncio
    async def test_400_non_action_not_found_does_not_mark_unsupported(self, api):
        """HTTP 400 without 'action not found' in body should not mark action unsupported."""
        resp = MagicMock()
        resp.status = 400
        resp.text = AsyncMock(return_value='{"error": "bad request"}')
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.closed = False
        session.patch = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            await api.send_action("display_on")

        assert "display_on" not in api._unsupported_actions

    @pytest.mark.asyncio
    async def test_uses_action_id_from_nested_type_map(self, api):
        """send_action uses UUID populated from device['type']['supportedActions']."""
        known_uuid = "06ad25d0-b087-46de-8e9b-7b18339e7238"
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

        # Simulate get_devices populating the map from nested type.supportedActions.
        async def fake_get_devices():
            api._action_id_map["display_on"] = known_uuid
            return []

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            with patch.object(api, "get_devices", AsyncMock(side_effect=fake_get_devices)):
                await api.send_action("display_on")

        assert captured_body["id"] == known_uuid
        assert captured_body["name"] == "display_on"


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
        device_data = [{"id": "dev-id", "brightness": 80, "volume": 50, "displayState": "on"}]
        resp = _mock_response(status=200, json_data=device_data)
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_device_status()
        assert result["brightness"] == 80
        assert result["state"] == "on"

    @pytest.mark.asyncio
    async def test_returns_empty_dict_when_device_id_not_found(self, api):
        """Returns empty dict when device ID is not found in the devices list."""
        device_data = [{"id": "other-dev", "brightness": 80}]
        resp = _mock_response(status=200, json_data=device_data)
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)
        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_device_status()
        assert result == {}

    @pytest.mark.asyncio
    async def test_reauths_on_401(self, api):
        resp_401 = _mock_response(status=401)
        resp_200 = _mock_response(status=200, json_data=[{"id": "dev-id", "brightness": 70}])

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
        resp_200 = _mock_response(status=200, json_data=[{"id": "dev-id", "brightness": 60}])

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
# _update_action_id_map / _update_action_id_map_from_device
# ---------------------------------------------------------------------------

class TestActionIdMap:
    @pytest.fixture
    def api(self):
        return UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")

    def test_update_from_device_populates_map(self, api):
        device = {
            "id": "dev-id",
            "supportedActions": [
                {"id": "uuid-1", "name": "display_on"},
                {"id": "uuid-2", "name": "display_off"},
            ],
        }
        api._update_action_id_map_from_device(device)
        assert api._action_id_map["display_on"] == "uuid-1"
        assert api._action_id_map["display_off"] == "uuid-2"

    def test_update_from_device_ignores_missing_fields(self, api):
        device = {
            "supportedActions": [
                {"id": "uuid-1"},           # missing name
                {"name": "display_on"},     # missing id
                {"id": "uuid-3", "name": "reboot"},
            ],
        }
        api._update_action_id_map_from_device(device)
        assert "display_on" not in api._action_id_map
        assert api._action_id_map["reboot"] == "uuid-3"

    def test_update_from_device_handles_missing_supported_actions(self, api):
        api._update_action_id_map_from_device({"id": "dev-id"})
        assert api._action_id_map == {}

    def test_update_from_device_handles_non_list_supported_actions(self, api):
        api._update_action_id_map_from_device({"supportedActions": "not-a-list"})
        assert api._action_id_map == {}

    def test_update_from_device_nested_under_type(self, api):
        """supportedActions nested under device['type'] is supported (firmware >= 1.13.6)."""
        device = {
            "id": "dev-id",
            "type": {
                "supportedActions": [
                    {"id": "06ad25d0-b087-46de-8e9b-7b18339e7238", "name": "display_on"},
                    {"id": "ea959362-c56f-4932-ab8b-0f512a93460c", "name": "display_off"},
                ],
            },
        }
        api._update_action_id_map_from_device(device)
        assert api._action_id_map["display_on"] == "06ad25d0-b087-46de-8e9b-7b18339e7238"
        assert api._action_id_map["display_off"] == "ea959362-c56f-4932-ab8b-0f512a93460c"

    def test_update_from_device_nested_under_type_category(self, api):
        """supportedActions nested under device['type']['category'] is supported."""
        device = {
            "id": "dev-id",
            "type": {
                "category": {
                    "supportedActions": [
                        {"id": "uuid-cat-on", "name": "display_on"},
                        {"id": "uuid-cat-off", "name": "display_off"},
                    ],
                },
            },
        }
        api._update_action_id_map_from_device(device)
        assert api._action_id_map["display_on"] == "uuid-cat-on"
        assert api._action_id_map["display_off"] == "uuid-cat-off"

    def test_update_from_device_top_level_takes_priority_over_type(self, api):
        """Top-level supportedActions takes priority over device['type']['supportedActions']."""
        device = {
            "id": "dev-id",
            "supportedActions": [{"id": "top-uuid", "name": "display_on"}],
            "type": {
                "supportedActions": [{"id": "nested-uuid", "name": "display_on"}],
            },
        }
        api._update_action_id_map_from_device(device)
        assert api._action_id_map["display_on"] == "top-uuid"

    def test_update_from_device_nested_under_typefk(self, api):
        """supportedActions nested under device['typeFK'] is supported."""
        device = {
            "id": "dev-id",
            "typeFK": {
                "supportedActions": [
                    {"id": "uuid-fk-on", "name": "display_on"},
                    {"id": "uuid-fk-off", "name": "display_off"},
                ],
            },
        }
        api._update_action_id_map_from_device(device)
        assert api._action_id_map["display_on"] == "uuid-fk-on"
        assert api._action_id_map["display_off"] == "uuid-fk-off"

    def test_update_from_device_nested_under_typefk_category(self, api):
        """supportedActions nested under device['typeFK']['category'] is supported."""
        device = {
            "id": "dev-id",
            "typeFK": {
                "category": {
                    "supportedActions": [
                        {"id": "uuid-fkcat-on", "name": "display_on"},
                        {"id": "uuid-fkcat-off", "name": "display_off"},
                    ],
                },
            },
        }
        api._update_action_id_map_from_device(device)
        assert api._action_id_map["display_on"] == "uuid-fkcat-on"
        assert api._action_id_map["display_off"] == "uuid-fkcat-off"

    def test_update_from_device_nested_under_feature_flags(self, api):
        """supportedActions nested under device['featureFlags'] is supported."""
        device = {
            "id": "dev-id",
            "featureFlags": {
                "supportedActions": [
                    {"id": "uuid-ff-on", "name": "display_on"},
                    {"id": "uuid-ff-off", "name": "display_off"},
                ],
            },
        }
        api._update_action_id_map_from_device(device)
        assert api._action_id_map["display_on"] == "uuid-ff-on"
        assert api._action_id_map["display_off"] == "uuid-ff-off"

    def test_update_action_id_map_nested_type_supported_actions(self, api):
        """_update_action_id_map finds matching device with nested type.supportedActions."""
        devices = [
            {
                "id": "dev-id",
                "type": {
                    "supportedActions": [
                        {"id": "06ad25d0-b087-46de-8e9b-7b18339e7238", "name": "display_on"},
                        {"id": "ea959362-c56f-4932-ab8b-0f512a93460c", "name": "display_off"},
                    ],
                },
            },
        ]
        api._update_action_id_map(devices)
        assert api._action_id_map["display_on"] == "06ad25d0-b087-46de-8e9b-7b18339e7238"
        assert api._action_id_map["display_off"] == "ea959362-c56f-4932-ab8b-0f512a93460c"

    def test_update_action_id_map_finds_matching_device(self, api):
        devices = [
            {"id": "other-dev", "supportedActions": [{"id": "x", "name": "display_on"}]},
            {
                "id": "dev-id",
                "supportedActions": [{"id": "uuid-correct", "name": "display_on"}],
            },
        ]
        api._update_action_id_map(devices)
        assert api._action_id_map["display_on"] == "uuid-correct"

    def test_update_action_id_map_no_matching_device(self, api):
        devices = [
            {"id": "other-dev", "supportedActions": [{"id": "x", "name": "display_on"}]},
        ]
        api._update_action_id_map(devices)
        assert api._action_id_map == {}

    def test_get_device_status_updates_action_id_map(self, api):
        """get_device_status() updates the action ID map when supportedActions present."""
        import asyncio

        async def _run():
            api._csrf_token = "csrf"
            device_data = [
                {
                    "id": "dev-id",
                    "brightness": 80,
                    "supportedActions": [
                        {"id": "uuid-on", "name": "display_on"},
                        {"id": "uuid-off", "name": "display_off"},
                    ],
                }
            ]
            resp = _mock_response(status=200, json_data=device_data)
            session = MagicMock()
            session.closed = False
            session.get = MagicMock(return_value=resp)
            with patch.object(api, "_get_session", AsyncMock(return_value=session)):
                await api.get_device_status()

        asyncio.get_event_loop().run_until_complete(_run())
        assert api._action_id_map["display_on"] == "uuid-on"
        assert api._action_id_map["display_off"] == "uuid-off"

# ---------------------------------------------------------------------------
# End-to-end: get_device_status returns all SENSOR_TYPES fields
# ---------------------------------------------------------------------------

class TestGetDeviceStatusAllSensors:
    """Confirm that get_device_status() surfaces values for every SENSOR_TYPES key.

    This class exercises the full pipeline:
        collection endpoint response
        → _parse_devices_response (list unwrap)
        → get_device_status (device ID match)
        → _parse_device_status (camelCase → snake_case mapping)
        → coordinator.data.get(sensor_key)   (what each sensor entity reads)

    Two device layouts are tested: one where each API field is already in
    snake_case and one where field names are camelCase (as the real UniFi
    Connect API returns them).
    """

    @pytest.fixture
    def api(self):
        api = UniFiDisplayAPI("192.168.1.100", "admin", "pass", "dev-id")
        api._csrf_token = "existing-csrf"
        return api

    @pytest.mark.asyncio
    async def test_all_sensor_types_resolved_from_camel_case_collection_response(self, api):
        """All 7 SENSOR_TYPES keys resolve when the API uses camelCase field names."""
        # This is the typical UniFi Connect API shape returned by the
        # collection endpoint GET /proxy/connect/api/v2/devices/.
        device = {
            "id": "dev-id",
            "name": "Living Room Display",
            "brightness": 80,
            "volume": 50,
            "displayState": "on",        # → state
            "ipAddress": "192.168.1.50", # → ip
            "hostname": "display-1",
            "screenResolution": "1920x1080",  # → resolution
            "linkQuality": 95,           # → link_quality
        }
        resp = _mock_response(status=200, json_data=[device])
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_device_status()

        assert result["brightness"] == 80
        assert result["volume"] == 50
        assert result["state"] == "on"
        assert result["ip"] == "192.168.1.50"
        assert result["hostname"] == "display-1"
        assert result["resolution"] == "1920x1080"
        assert result["link_quality"] == 95

    @pytest.mark.asyncio
    async def test_all_sensor_types_resolved_from_snake_case_collection_response(self, api):
        """All 7 SENSOR_TYPES keys resolve when the API already uses snake_case field names."""
        device = {
            "id": "dev-id",
            "brightness": 80,
            "volume": 50,
            "state": "on",
            "ip": "192.168.1.50",
            "hostname": "display-1",
            "resolution": "1920x1080",
            "link_quality": 95,
        }
        resp = _mock_response(status=200, json_data=[device])
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_device_status()

        assert result["brightness"] == 80
        assert result["volume"] == 50
        assert result["state"] == "on"
        assert result["ip"] == "192.168.1.50"
        assert result["hostname"] == "display-1"
        assert result["resolution"] == "1920x1080"
        assert result["link_quality"] == 95

    @pytest.mark.asyncio
    async def test_all_sensor_types_resolved_from_wrapper_collection_response(self, api):
        """All 7 SENSOR_TYPES keys resolve when the collection endpoint wraps the list."""
        device = {
            "id": "dev-id",
            "brightness": 70,
            "volume": 40,
            "displayState": "sleep",     # → state
            "ipAddress": "10.0.0.5",     # → ip
            "hostname": "display-2",
            "displayResolution": "3840x2160",  # → resolution
            "wifiQuality": 88,           # → link_quality
        }
        wrapper = {"err": None, "type": "collection", "data": [device]}
        resp = _mock_response(status=200, json_data=wrapper)
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_device_status()

        assert result["brightness"] == 70
        assert result["volume"] == 40
        assert result["state"] == "sleep"
        assert result["ip"] == "10.0.0.5"
        assert result["hostname"] == "display-2"
        assert result["resolution"] == "3840x2160"
        assert result["link_quality"] == 88

    @pytest.mark.asyncio
    async def test_power_switch_state_resolves_from_shadow_display(self, api):
        """display_on is extracted from shadow.display for the power switch."""
        device = {
            "id": "dev-id",
            "state": "ADOPTED",
            "ipAddress": "192.168.1.50",
            "hostname": "display-1",
            "shadow": {
                "display": True,
                "brightness": 200,
                "volume": 20,
                "sleepMode": False,
                "autoReload": False,
                "autoRotate": True,
                "memorizePlaylist": False,
            },
        }
        resp = _mock_response(status=200, json_data=[device])
        session = MagicMock()
        session.closed = False
        session.get = MagicMock(return_value=resp)

        with patch.object(api, "_get_session", AsyncMock(return_value=session)):
            result = await api.get_device_status()

        # Power switch now reads display_on from shadow.display.
        assert result["display_on"] is True
        assert result["state"] == "ADOPTED"
        # Shadow fields are also flattened.
        assert result["brightness"] == 200
        assert result["volume"] == 20
        assert result["sleep_mode"] is False
        assert result["auto_reload"] is False
        assert result["auto_rotate"] is True
        assert result["memorize_playlist"] is False
        # STATE_KEY_MAP maps enable_sleep -> sleep_mode, etc.
        assert STATE_KEY_MAP["enable_sleep"] == "sleep_mode"
        assert STATE_KEY_MAP["enable_auto_reload"] == "auto_reload"


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
