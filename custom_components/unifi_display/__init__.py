# __init__.py - Initializes the UniFi Connect Display integration for Home Assistant

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import CannotConnectError, UniFiDisplayAPI
from .const import (
    CONF_DEVICE_ID,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor", "number", "switch", "select", "button"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up UniFi Connect Display from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    api = UniFiDisplayAPI(
        host=entry.data[CONF_HOST],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        device_id=entry.data[CONF_DEVICE_ID],
        verify_ssl=entry.data.get(CONF_VERIFY_SSL, False),
    )

    # Verify connectivity at startup.
    try:
        await api.authenticate()
    except CannotConnectError as exc:
        await api.close()
        raise ConfigEntryNotReady(f"Cannot connect to UniFi controller: {exc}") from exc

    async def _async_update_data() -> dict:
        """Fetch current device status from the API."""
        try:
            return await api.get_device_status()
        except CannotConnectError as exc:
            raise UpdateFailed(f"Error communicating with device: {exc}") from exc

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"{DOMAIN}_{entry.entry_id}",
        update_method=_async_update_data,
        update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
    )

    # Perform an initial data fetch so entities have data on first render.
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and close the API session."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id, {})
        api: UniFiDisplayAPI | None = entry_data.get("api")
        if api:
            await api.close()
    return unload_ok

