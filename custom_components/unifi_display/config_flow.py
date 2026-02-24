"""Config flow for UniFi Connect Display."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .api import AuthenticationError, CannotConnectError, UniFiDisplayAPI
from .const import (
    CONF_DEVICE_ID,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_NO_DEVICES,
    ERROR_UNKNOWN,
    NAME,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_VERIFY_SSL, default=False): bool,
    }
)


class UniFiDisplayConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the config flow for UniFi Connect Display."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialise the flow."""
        self._host: str = ""
        self._username: str = ""
        self._password: str = ""
        self._verify_ssl: bool = False
        self._devices: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Step 1: credentials
    # ------------------------------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask the user for controller credentials."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._host = user_input[CONF_HOST]
            self._username = user_input[CONF_USERNAME]
            self._password = user_input[CONF_PASSWORD]
            self._verify_ssl = user_input.get(CONF_VERIFY_SSL, False)

            # Attempt authentication and device discovery.
            try:
                api = UniFiDisplayAPI(
                    host=self._host,
                    username=self._username,
                    password=self._password,
                    device_id="",  # Not needed for discovery
                    verify_ssl=self._verify_ssl,
                )
                await api.authenticate()
                self._devices = await api.get_devices()
                await api.close()
            except AuthenticationError:
                errors["base"] = ERROR_INVALID_AUTH
            except CannotConnectError:
                errors["base"] = ERROR_CANNOT_CONNECT
            except Exception:  # noqa: BLE001
                # Catch-all for truly unexpected errors (e.g. library bugs).
                # The specific exception is logged so it is still visible in
                # the Home Assistant log for debugging.
                _LOGGER.exception("Unexpected error during config flow")
                errors["base"] = ERROR_UNKNOWN

            if not errors:
                if not self._devices:
                    errors["base"] = ERROR_NO_DEVICES
                elif len(self._devices) == 1:
                    # Auto-select the only device.
                    return self._create_entry(self._devices[0])
                else:
                    return await self.async_step_device()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Step 2: device selection (only shown when > 1 device found)
    # ------------------------------------------------------------------

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Let the user choose which display to control."""
        errors: dict[str, str] = {}

        if user_input is not None:
            device_id = user_input[CONF_DEVICE_ID]
            device = next(
                (d for d in self._devices if d.get("id") == device_id), None
            )
            if device:
                return self._create_entry(device)
            errors["base"] = ERROR_UNKNOWN

        device_options = {
            d["id"]: d.get("name", d["id"]) for d in self._devices if "id" in d
        }

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema(
                {vol.Required(CONF_DEVICE_ID): vol.In(device_options)}
            ),
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _create_entry(self, device: dict[str, Any]) -> FlowResult:
        """Create the config entry from discovered device data."""
        device_id = device.get("id", "")
        device_name = device.get("name", device_id)

        return self.async_create_entry(
            title=f"{NAME} – {device_name}",
            data={
                CONF_HOST: self._host,
                CONF_USERNAME: self._username,
                CONF_PASSWORD: self._password,
                CONF_DEVICE_ID: device_id,
                CONF_VERIFY_SSL: self._verify_ssl,
            },
        )

