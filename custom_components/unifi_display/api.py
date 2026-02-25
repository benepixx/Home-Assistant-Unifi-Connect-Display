"""UniFi Connect Display API client.

Authentication flow (mirrored from working shell scripts):
  1. POST /api/auth/login  →  receives a TOKEN cookie (JWT).
  2. Decode the JWT payload (base64) and extract the ``csrfToken`` field.
  3. All subsequent requests include the session cookie *and* the
     ``X-CSRF-Token`` header obtained in step 2.
  4. Display actions are sent as PATCH requests to
     /proxy/connect/api/v2/devices/{device_id}/status with a JSON body of
     ``{"id": "<uuid>", "name": "<action>", "args": {...}}``.
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
        return headers

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
        except aiohttp.ClientError as exc:
            raise CannotConnectError(str(exc)) from exc

        # Extract CSRF token from the TOKEN cookie (JWT).
        cookies = session.cookie_jar.filter_cookies(url)
        _LOGGER.debug(
            "Cookies after login: %s",
            {k: v.value for k, v in cookies.items()},
        )
        token_cookie = cookies.get("TOKEN")
        if token_cookie:
            self._token = token_cookie.value
            self._csrf_token = self._extract_csrf_from_jwt(token_cookie.value)
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
                if resp.status == 401:
                    await self.authenticate()
                    async with session.get(
                        url, headers=self._auth_headers()
                    ) as retry:
                        data = await retry.json(content_type=None)
                        return data if isinstance(data, list) else []
                data = await resp.json(content_type=None)
                return data if isinstance(data, list) else []
        except aiohttp.ClientError as exc:
            raise CannotConnectError(str(exc)) from exc

    # ------------------------------------------------------------------
    # Device status
    # ------------------------------------------------------------------

    async def get_device_status(self) -> dict[str, Any]:
        """Fetch and return the current status of the configured device.

        Re-authenticates once automatically on HTTP 401.

        Returns:
            A dictionary with device status fields (brightness, volume,
            state, ip, hostname, resolution, link_quality, etc.).

        Raises:
            CannotConnectError: The controller could not be reached.
        """
        if self._csrf_token is None:
            await self.authenticate()

        session = await self._get_session()
        url = f"{self._host}{API_DEVICE_STATUS_PATH.format(device_id=self._device_id)}"

        try:
            async with session.get(url, headers=self._auth_headers()) as resp:
                if resp.status == 401:
                    await self.authenticate()
                    async with session.get(
                        url, headers=self._auth_headers()
                    ) as retry:
                        data = await retry.json(content_type=None)
                        return data if isinstance(data, dict) else {}
                data = await resp.json(content_type=None)
                return data if isinstance(data, dict) else {}
        except aiohttp.ClientError as exc:
            raise CannotConnectError(str(exc)) from exc

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

        session = await self._get_session()
        url = f"{self._host}{API_DEVICE_STATUS_PATH.format(device_id=self._device_id)}"
        body = {
            "id": str(uuid.uuid4()),
            "name": action_name,
            "args": args or {},
        }
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-CSRF-Token": self._csrf_token or "",
            "Origin": self._host,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            async with session.patch(url, json=body, headers=headers) as resp:
                if resp.status == 401:
                    await self.authenticate()
                    headers["X-CSRF-Token"] = self._csrf_token or ""
                    if self._token:
                        headers["Authorization"] = f"Bearer {self._token}"
                    else:
                        headers.pop("Authorization", None)
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
