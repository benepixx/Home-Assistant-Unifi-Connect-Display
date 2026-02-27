"""UniFi Connect Display API client.

Authentication flow (mirrored from working shell scripts):
  1. POST /api/auth/login  →  receives a TOKEN cookie (JWT).
  2. CSRF token is extracted from response headers ``X-Updated-Csrf-Token`` /
     ``X-CSRF-Token`` (current controllers), or from the JWT payload
     ``csrfToken`` field (legacy fallback).
  3. All subsequent requests include the session cookie *and* the
     ``X-CSRF-Token`` header obtained in step 2.
  4. Display actions are sent as PATCH requests to
     /proxy/connect/api/v2/devices/{device_id}/status with a JSON body of
     ``{"id": "<supported_action_uuid>", "name": "<action>", "args": {...}}``.
     The ``id`` must be the UUID from ``supportedActions`` for the device,
     not a random UUID.
"""
from __future__ import annotations

import base64
import json
import logging
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

from .const import (
    API_DEVICES_PATH,
    API_DEVICE_STATUS_PATH,
    API_LOGIN_PATH,
)

_LOGGER = logging.getLogger(__name__)


def _parse_devices_response(data: Any) -> list[dict[str, Any]]:
    """Parse a devices API response into a list of device dicts.

    Handles both a bare list and a wrapper object with a ``data`` key,
    e.g. ``{"err": null, "type": "collection", "data": [...], ...}``.
    """
    if isinstance(data, list):
        _LOGGER.debug("Devices response: bare list with %d item(s)", len(data))
        return data
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        devices = data["data"]
        _LOGGER.debug(
            "Devices response: wrapper object with %d item(s)", len(devices)
        )
        return devices
    _LOGGER.debug(
        "Devices response: unexpected format %s; returning empty list",
        type(data).__name__,
    )
    return []


class AuthenticationError(Exception):
    """Raised when authentication with the UniFi controller fails."""


class CannotConnectError(Exception):
    """Raised when the integration cannot reach the UniFi controller."""


class UniFiDisplayAPI:
    """Async API client for the UniFi Connect Display."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        device_id: str,
        verify_ssl: bool = False,
    ) -> None:
        """Initialise the client.

        Args:
            host: IP address or hostname of the UniFi controller.  The
                ``https://`` scheme is prepended automatically if absent.
            username: UniFi controller username.
            password: UniFi controller password.
            device_id: UUID of the target display device.
            verify_ssl: Whether to verify the server TLS certificate.
                Defaults to ``False`` because most home installations use
                self-signed certificates.
        """
        # Normalise host – strip trailing slash, add https:// if needed.
        host = host.rstrip("/")
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        parsed = urlparse(host)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid host URL after normalisation: {host!r}")
        self._host = host
        self._username = username
        self._password = password
        self._device_id = device_id
        self._verify_ssl = verify_ssl

        self._session: Optional[aiohttp.ClientSession] = None
        self._csrf_token: Optional[str] = None
        self._token: Optional[str] = None
        # Maps supported action name → supported action UUID for this device.
        # Populated from ``supportedActions`` in device API responses.
        self._action_id_map: dict[str, str] = {}
        # Actions that returned HTTP 400 "action not found" from the controller.
        # Entries here are treated as unsupported for this device/firmware.
        self._unsupported_actions: set[str] = set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_connector(self) -> aiohttp.TCPConnector:
        """Return a TCP connector with optional SSL verification.

        ``ssl=False`` is the aiohttp-specific way to disable certificate
        verification entirely (as opposed to ``ssl=None`` which uses the
        default SSL context and verifies the certificate).
        """
        ssl_context = None if self._verify_ssl else False
        return aiohttp.TCPConnector(ssl=ssl_context)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return an open aiohttp session, creating one if necessary."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=self._make_connector()
            )
        return self._session

    @staticmethod
    def _extract_token_from_set_cookie_headers(headers) -> Optional[str]:
        """Extract the TOKEN value by parsing ``Set-Cookie`` response headers.

        This handles controllers that return cookies with the ``Partitioned``
        attribute (CHIPS), which some cookie jars reject or ignore.

        Args:
            headers: The response headers object.  Supports ``getall`` for
                multi-value header access (e.g. aiohttp's
                ``CIMultiDictProxy``), or falls back to a plain mapping.

        Returns:
            The raw TOKEN cookie value string, or ``None`` if not found.
        """
        try:
            set_cookie_values = (
                headers.getall("Set-Cookie", [])
                if hasattr(headers, "getall")
                else ([headers["Set-Cookie"]] if "Set-Cookie" in headers else [])
            )
        except Exception:  # noqa: BLE001
            return None
        for cookie_str in set_cookie_values:
            # Each Set-Cookie value: name=value[; attr[; attr=val ...]]
            name_value = cookie_str.split(";")[0].strip()
            if name_value.startswith("TOKEN="):
                return name_value[len("TOKEN="):]
        return None

    @staticmethod
    def _extract_csrf_from_jwt(jwt_token: str) -> Optional[str]:
        """Decode a JWT and return the ``csrfToken`` claim, or ``None``."""
        try:
            parts = jwt_token.split(".")
            if len(parts) < 2:
                return None
            # Base64-URL decode with padding correction.
            payload_b64 = parts[1]
            padding = (4 - len(payload_b64) % 4) % 4
            payload_b64 += "=" * padding
            payload = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
            return payload.get("csrfToken")
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("Failed to extract CSRF token from JWT: %s", exc)
            return None

    def _auth_headers(self) -> dict[str, str]:
        """Return headers required for authenticated requests."""
        headers: dict[str, str] = {"Origin": self._host}
        if self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
            headers["Cookie"] = f"TOKEN={self._token}"
        return headers

    def _update_action_id_map_from_device(self, device: dict[str, Any]) -> None:
        """Update ``_action_id_map`` from ``supportedActions`` in a device dict.

        Args:
            device: A single device dictionary (already unwrapped from any
                API wrapper).  The ``supportedActions`` key, if present,
                is expected to be a list of ``{"id": <uuid>, "name": <str>}``
                objects.
        """
        supported = device.get("supportedActions")
        if not isinstance(supported, list):
            # Also check device["type"]["category"]["supportedActions"]
            # (firmware >= 1.13.6 nests actions under type.category).
            # Fall back to device["type"]["supportedActions"] for older firmware.
            type_info = device.get("type")
            if isinstance(type_info, dict):
                category = type_info.get("category")
                if isinstance(category, dict):
                    supported = category.get("supportedActions", [])
                else:
                    supported = type_info.get("supportedActions", [])
            else:
                supported = []
        if not isinstance(supported, list):
            return
        new_entries: dict[str, str] = {}
        for action in supported:
            if not isinstance(action, dict):
                continue
            name = action.get("name")
            uid = action.get("id")
            if name and uid:
                new_entries[name] = uid
        if new_entries:
            self._action_id_map.update(new_entries)
            _LOGGER.debug(
                "Updated action ID map with %d entry/entries for device %s",
                len(self._action_id_map),
                self._device_id,
            )

    def _update_action_id_map(self, devices: list[dict[str, Any]]) -> None:
        """Update ``_action_id_map`` from the matching device in a device list.

        Args:
            devices: List of device dicts as returned by the devices endpoint.
        """
        for device in devices:
            if isinstance(device, dict) and device.get("id") == self._device_id:
                self._update_action_id_map_from_device(device)
                return

    def is_action_supported(self, action_name: str) -> bool:
        """Return whether ``action_name`` is supported by this device.

        An action is considered unsupported once the controller has
        returned HTTP 400 "action not found" for it.  Until the controller
        confirms the action is unsupported, this returns ``True`` so that
        entities remain available by default.

        Args:
            action_name: The action name to check (e.g. ``"display_on"``).

        Returns:
            ``False`` if the controller has rejected this action as unknown;
            ``True`` otherwise.
        """
        return action_name not in self._unsupported_actions

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def authenticate(self) -> None:
        """Log in and capture the CSRF token from the returned JWT cookie.

        Raises:
            AuthenticationError: Credentials were rejected or the response
                did not contain the expected user data.
            CannotConnectError: The controller could not be reached.
        """
        # Reset stored auth state before a fresh login attempt.
        self._csrf_token = None
        self._token = None

        session = await self._get_session()
        url = f"{self._host}{API_LOGIN_PATH}"
        _LOGGER.debug("Authenticating against URL: %s", url)
        payload = {"username": self._username, "password": self._password}

        token_from_headers: Optional[str] = None
        csrf_from_response_header: Optional[str] = None
        try:
            async with session.post(url, json=payload) as resp:
                _LOGGER.debug(
                    "Login response: HTTP %s, headers=%s",
                    resp.status,
                    dict(resp.headers),
                )
                try:
                    body = await resp.json(content_type=None)
                except Exception:
                    body = {}

                _LOGGER.debug("Login response body: %s", body)

                if resp.status != 200:
                    raise AuthenticationError(
                        f"Login failed (HTTP {resp.status}): {body}"
                    )
                # The UniFi controller returns a JSON object containing
                # ``unique_id`` or similar user fields on success.
                if not isinstance(body, dict) or (
                    "unique_id" not in body and "userId" not in body
                ):
                    raise AuthenticationError(
                        f"Unexpected login response body: {body}"
                    )

                # Capture TOKEN from Set-Cookie headers while the response is
                # still open.  This handles controllers that set the cookie
                # with the ``Partitioned`` attribute, which some cookie jars
                # reject or ignore.
                token_from_headers = self._extract_token_from_set_cookie_headers(
                    resp.headers
                )
                # Prefer CSRF from response headers (current controllers send
                # it via ``X-Updated-Csrf-Token`` or ``X-CSRF-Token``).
                csrf_from_response_header = (
                    resp.headers.get("X-Updated-Csrf-Token")
                    or resp.headers.get("X-CSRF-Token")
                )
                _LOGGER.debug(
                    "CSRF from response header: %s",
                    bool(csrf_from_response_header),
                )
        except aiohttp.ClientError as exc:
            raise CannotConnectError(str(exc)) from exc

        # Prefer the token parsed directly from Set-Cookie headers (handles
        # the ``Partitioned`` / CHIPS attribute).  Fall back to the cookie jar
        # for older controllers where the attribute is absent and the jar works.
        if token_from_headers:
            self._token = token_from_headers
            # Prefer CSRF from response header; fall back to JWT extraction.
            self._csrf_token = (
                csrf_from_response_header
                or self._extract_csrf_from_jwt(token_from_headers)
            )
            _LOGGER.debug(
                "TOKEN recovered from Set-Cookie header parsing (len=%d).",
                len(token_from_headers),
            )
            if not self._csrf_token:
                _LOGGER.warning(
                    "Logged in successfully but could not extract CSRF token "
                    "from TOKEN cookie; some requests may fail."
                )
            else:
                _LOGGER.debug("CSRF token extracted successfully.")
            return

        # Fall back to cookie jar (older controllers without Partitioned).
        cookies = session.cookie_jar.filter_cookies(url)
        _LOGGER.debug(
            "Cookies after login: %s",
            {k: v.value for k, v in cookies.items()},
        )
        token_cookie = cookies.get("TOKEN")
        if token_cookie:
            self._token = token_cookie.value
            # Prefer CSRF from response header; fall back to JWT extraction.
            self._csrf_token = (
                csrf_from_response_header
                or self._extract_csrf_from_jwt(token_cookie.value)
            )
            _LOGGER.debug(
                "TOKEN obtained from cookie jar (len=%d).",
                len(self._token),
            )
            if not self._csrf_token:
                _LOGGER.warning(
                    "Logged in successfully but could not extract CSRF token "
                    "from TOKEN cookie; some requests may fail."
                )
            else:
                _LOGGER.debug("CSRF token extracted successfully.")
        else:
            _LOGGER.warning(
                "TOKEN cookie not found after login; "
                "authenticated requests may fail."
            )

    # ------------------------------------------------------------------
    # Device discovery
    # ------------------------------------------------------------------

    async def get_devices(self) -> list[dict[str, Any]]:
        """Return the list of UniFi Connect devices from the controller.

        Re-authenticates once automatically on HTTP 401.

        Returns:
            A list of device dictionaries as returned by the API.

        Raises:
            CannotConnectError: The controller could not be reached.
            AuthenticationError: Authentication failed on retry.
        """
        if self._csrf_token is None:
            await self.authenticate()

        session = await self._get_session()
        url = f"{self._host}{API_DEVICES_PATH}"

        try:
            async with session.get(url, headers=self._auth_headers()) as resp:
                if resp.status in (401, 403):
                    await self.authenticate()
                    async with session.get(
                        url, headers=self._auth_headers()
                    ) as retry:
                        data = await retry.json(content_type=None)
                        devices = _parse_devices_response(data)
                        self._update_action_id_map(devices)
                        return devices
                data = await resp.json(content_type=None)
                devices = _parse_devices_response(data)
                self._update_action_id_map(devices)
                return devices
        except aiohttp.ClientError as exc:
            raise CannotConnectError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Device status
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_device_status(data: Any) -> dict[str, Any]:
        """Unwrap and normalise a single-device API response.

        Handles two common response shapes:
        * ``{"data": {...}, "err": null, ...}`` – wrapper object
        * ``{...}``                             – bare device dict

        Also flattens ``shadow`` and ``extraInfo`` sub-objects and maps
        camelCase / alternate key names to the snake_case keys expected by
        the sensor/number/switch platforms.
        """
        if not isinstance(data, dict):
            _LOGGER.debug("_parse_device_status: unexpected type %s", type(data).__name__)
            return {}
        # Unwrap wrapper format {"data": {...}}
        if "data" in data and isinstance(data["data"], dict):
            data = data["data"]
        _LOGGER.debug("Device status raw keys: %s", list(data.keys()))
        # Normalise common alternative key names to what SENSOR_TYPES expects.
        normalized: dict[str, Any] = dict(data)
        key_map = {
            "displayState": "state",
            "display_state": "state",
            "ipAddress": "ip",
            "ip_address": "ip",
            "linkQuality": "link_quality",
            "wifi_quality": "link_quality",
            "wifiQuality": "link_quality",
            "signalQuality": "link_quality",
            "signal_quality": "link_quality",
            "displayResolution": "resolution",
            "screen_resolution": "resolution",
            "screenResolution": "resolution",
        }
        for api_key, sensor_key in key_map.items():
            if api_key in data and sensor_key not in normalized:
                normalized[sensor_key] = data[api_key]

        # Flatten shadow fields (brightness, volume, sleepMode, autoReload, etc.)
        shadow = data.get("shadow")
        if isinstance(shadow, dict):
            normalized["brightness"] = shadow.get("brightness")
            normalized["volume"] = shadow.get("volume")
            normalized["sleep_mode"] = shadow.get("sleepMode")
            normalized["auto_reload"] = shadow.get("autoReload")
            normalized["auto_rotate"] = shadow.get("autoRotate")
            normalized["memorize_playlist"] = shadow.get("memorizePlaylist")
            normalized["display_on"] = shadow.get("display", False)
            normalized["mode"] = shadow.get("mode")
            # Determine current app from appList (entry with selected=True).
            app_list = shadow.get("appList")
            if isinstance(app_list, list):
                for app in app_list:
                    if isinstance(app, dict) and app.get("selected"):
                        normalized["current_app"] = app.get("apkId") or app.get("id")
                        break

        # Flatten extraInfo fields (resolution, linkQuality, etc.)
        extra_info = data.get("extraInfo")
        if isinstance(extra_info, dict):
            if "resolution" not in normalized or normalized.get("resolution") is None:
                normalized["resolution"] = extra_info.get("resolution")
            if "link_quality" not in normalized or normalized.get("link_quality") is None:
                normalized["link_quality"] = extra_info.get("linkQuality")

        return normalized

    async def get_device_status(self) -> dict[str, Any]:
        """Fetch and return the current status of the configured device.

        Retrieves the full device list from the controller via the
        collection endpoint (``GET /proxy/connect/api/v2/devices/``) and
        returns the parsed status for the device matching ``_device_id``.
        Re-authentication is handled automatically by :meth:`get_devices`.

        Returns:
            A dictionary with device status fields (brightness, volume,
            state, ip, hostname, resolution, link_quality, etc.).
            Returns an empty dict if the device is not found in the list.

        Raises:
            CannotConnectError: The controller could not be reached.
        """
        devices = await self.get_devices()
        for device in devices:
            if isinstance(device, dict) and device.get("id") == self._device_id:
                return self._parse_device_status(device)
        _LOGGER.debug("Device %s not found in devices list", self._device_id)
        return {}

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def send_action(
        self, action_name: str, args: Optional[dict[str, Any]] = None
    ) -> bool:
        """Send a named action to the display.

        Args:
            action_name: One of the action names defined in ``const.py``
                (e.g. ``"display_on"``, ``"brightness"``, ``"load_website"``).
            args: Optional dictionary of action arguments
                (e.g. ``{"level": 80}`` for brightness).

        Returns:
            ``True`` if the request succeeded (HTTP 200/201/204).
        """
        if self._csrf_token is None:
            await self.authenticate()

        # If the action UUID is not yet known, try fetching the device list to
        # populate the map before falling back to a random UUID (which current
        # controller builds reject as "action not found").
        if action_name not in self._action_id_map:
            try:
                await self.get_devices()
            except Exception:  # noqa: BLE001
                pass

        session = await self._get_session()
        url = f"{self._host}{API_DEVICE_STATUS_PATH.format(device_id=self._device_id)}"
        # Auto-prepend http:// to load_website URL if no scheme is present.
        if action_name == "load_website" and args and "url" in args:
            raw_url = str(args["url"])
            if not raw_url.startswith(("http://", "https://")):
                args = dict(args)
                args["url"] = f"http://{raw_url}"
        # Use the supported action UUID if available; fall back to a random
        # UUID for backward compatibility with controllers that may not enforce
        # the action ID check.
        action_id = self._action_id_map.get(action_name) or str(uuid.uuid4())
        body = {
            "id": action_id,
            "name": action_name,
            "args": args or {},
        }
        # Match the browser/web-UI request: Cookie + X-CSRF-Token + Origin only.
        # Do NOT send an Authorization: Bearer header; some controller builds
        # reject action PATCH requests that include it and return HTTP 400.
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-CSRF-Token": self._csrf_token or "",
            "Origin": self._host,
        }
        if self._token:
            headers["Cookie"] = f"TOKEN={self._token}"

        try:
            async with session.patch(url, json=body, headers=headers) as resp:
                if resp.status not in (200, 201, 204):
                    try:
                        resp_body = await resp.text()
                    except Exception:  # noqa: BLE001
                        resp_body = "<unreadable>"
                    _LOGGER.debug(
                        "send_action '%s' (device=%s, url=%s): HTTP %s, response: %s",
                        action_name,
                        self._device_id,
                        url,
                        resp.status,
                        resp_body,
                    )
                    if resp.status == 400 and "action not found" in resp_body:
                        _LOGGER.warning(
                            "Action '%s' is not supported by device %s; "
                            "marking as unavailable to prevent further errors.",
                            action_name,
                            self._device_id,
                        )
                        self._unsupported_actions.add(action_name)
                if resp.status in (401, 403):
                    _LOGGER.debug(
                        "send_action '%s': HTTP %s, re-authenticating",
                        action_name,
                        resp.status,
                    )
                    await self.authenticate()
                    headers["X-CSRF-Token"] = self._csrf_token or ""
                    if self._token:
                        headers["Cookie"] = f"TOKEN={self._token}"
                    else:
                        headers.pop("Cookie", None)
                    async with session.patch(
                        url, json=body, headers=headers
                    ) as retry:
                        return retry.status in (200, 201, 204)
                return resp.status in (200, 201, 204)
        except aiohttp.ClientError as exc:
            _LOGGER.error("Error sending action '%s': %s", action_name, exc)
            return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
