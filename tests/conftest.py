"""Test configuration and shared fixtures for unifi_display tests."""
from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.unifi_display.api import UniFiDisplayAPI


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


@pytest.fixture
def mock_jwt():
    """Return a JWT string containing a known CSRF token."""
    return _make_jwt()


@pytest.fixture
def api_client():
    """Return a :class:`UniFiDisplayAPI` instance without a live session."""
    return UniFiDisplayAPI(
        host="192.168.1.100",
        username="admin",
        password="password",
        device_id="device-uuid-1234",
        verify_ssl=False,
    )
