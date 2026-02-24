"""Tests for the UniFi Connect Display config flow."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.unifi_display.config_flow import UniFiDisplayConfigFlow
from custom_components.unifi_display.const import (
    CONF_DEVICE_ID,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_NO_DEVICES,
)


SINGLE_DEVICE = [{"id": "dev-uuid-001", "name": "Living Room Display"}]
MULTI_DEVICES = [
    {"id": "dev-uuid-001", "name": "Living Room"},
    {"id": "dev-uuid-002", "name": "Bedroom"},
]

VALID_CREDENTIALS = {
    CONF_HOST: "192.168.1.100",
    CONF_USERNAME: "admin",
    CONF_PASSWORD: "secret",
    CONF_VERIFY_SSL: False,
}


def _mock_api(devices=None, auth_error=None, connect_error=None):
    """Return a patched :class:`UniFiDisplayAPI` constructor."""
    from custom_components.unifi_display.api import (
        AuthenticationError,
        CannotConnectError,
    )

    api_instance = MagicMock()
    if auth_error:
        api_instance.authenticate = AsyncMock(side_effect=AuthenticationError("bad creds"))
    elif connect_error:
        api_instance.authenticate = AsyncMock(side_effect=CannotConnectError("no route"))
    else:
        api_instance.authenticate = AsyncMock()

    api_instance.get_devices = AsyncMock(return_value=devices or [])
    api_instance.close = AsyncMock()

    return patch(
        "custom_components.unifi_display.config_flow.UniFiDisplayAPI",
        return_value=api_instance,
    )


class TestConfigFlowStepUser:
    """Tests for the initial credentials step."""

    @pytest.mark.asyncio
    async def test_shows_form_when_no_input(self):
        flow = UniFiDisplayConfigFlow()
        result = await flow.async_step_user(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "user"

    @pytest.mark.asyncio
    async def test_single_device_creates_entry_directly(self):
        with _mock_api(devices=SINGLE_DEVICE):
            flow = UniFiDisplayConfigFlow()
            result = await flow.async_step_user(user_input=VALID_CREDENTIALS)

        assert result["type"] == "create_entry"
        assert result["data"][CONF_DEVICE_ID] == "dev-uuid-001"
        assert result["data"][CONF_HOST] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_multiple_devices_goes_to_device_step(self):
        with _mock_api(devices=MULTI_DEVICES):
            flow = UniFiDisplayConfigFlow()
            result = await flow.async_step_user(user_input=VALID_CREDENTIALS)

        assert result["type"] == "form"
        assert result["step_id"] == "device"

    @pytest.mark.asyncio
    async def test_invalid_auth_shows_error(self):
        with _mock_api(auth_error=True):
            flow = UniFiDisplayConfigFlow()
            result = await flow.async_step_user(user_input=VALID_CREDENTIALS)

        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_INVALID_AUTH

    @pytest.mark.asyncio
    async def test_cannot_connect_shows_error(self):
        with _mock_api(connect_error=True):
            flow = UniFiDisplayConfigFlow()
            result = await flow.async_step_user(user_input=VALID_CREDENTIALS)

        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_no_devices_found_shows_error(self):
        with _mock_api(devices=[]):
            flow = UniFiDisplayConfigFlow()
            result = await flow.async_step_user(user_input=VALID_CREDENTIALS)

        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_NO_DEVICES


class TestConfigFlowStepDevice:
    """Tests for the device-selection step (shown when multiple devices exist)."""

    @pytest.mark.asyncio
    async def test_shows_device_selection_form(self):
        with _mock_api(devices=MULTI_DEVICES):
            flow = UniFiDisplayConfigFlow()
            await flow.async_step_user(user_input=VALID_CREDENTIALS)
            result = await flow.async_step_device(user_input=None)

        assert result["type"] == "form"
        assert result["step_id"] == "device"

    @pytest.mark.asyncio
    async def test_selecting_device_creates_entry(self):
        with _mock_api(devices=MULTI_DEVICES):
            flow = UniFiDisplayConfigFlow()
            await flow.async_step_user(user_input=VALID_CREDENTIALS)
            result = await flow.async_step_device(
                user_input={CONF_DEVICE_ID: "dev-uuid-002"}
            )

        assert result["type"] == "create_entry"
        assert result["data"][CONF_DEVICE_ID] == "dev-uuid-002"
