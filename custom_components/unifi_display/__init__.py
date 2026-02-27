# __init__.py - Initializes the UniFi Connect Display integration for Home Assistant

from __future__ import annotations

import logging
from datetime import timedelta

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import CannotConnectError, AuthenticationError, UniFiDisplayAPI
from .const import (
    CONF_DEVICE_ID,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    SERVICE_LAUNCH_APP,
    SERVICE_LOAD_WEBSITE,
    SERVICE_LOAD_YOUTUBE,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor", "number", "switch", "select", "button"]

SERVICE_LOAD_WEBSITE_SCHEMA = vol.Schema({vol.Required("url"): cv.string})
SERVICE_LAUNCH_APP_SCHEMA = vol.Schema({vol.Required("app_id"): cv.string})
SERVICE_LOAD_YOUTUBE_SCHEMA = vol.Schema({vol.Required("video_id"): cv.string})


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

    # Verify connectivity at startup and populate the supported-action UUID map.
    try:
        await api.authenticate()
        await api.get_devices()
    except CannotConnectError as exc:
        await api.close()
        raise ConfigEntryNotReady(f"Cannot connect to UniFi controller: {exc}") from exc

    async def _async_update_data() -> dict:
        """Fetch current device status from the API."""
        try:
            return await api.get_device_status()
        except CannotConnectError as exc:
            raise UpdateFailed(f"Error communicating with device: {exc}") from exc
        except AuthenticationError:
            _LOGGER.warning("Authentication expired during polling; re-authenticating")
            try:
                await api.authenticate()
                return await api.get_device_status()
            except (CannotConnectError, AuthenticationError) as exc:
                raise UpdateFailed(f"Re-authentication failed: {exc}") from exc

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

    if not hass.services.has_service(DOMAIN, SERVICE_LOAD_WEBSITE):

        async def _handle_load_website(call: ServiceCall) -> None:
            url = call.data["url"]
            for entry_data in hass.data[DOMAIN].values():
                await entry_data["api"].send_action("load_website", {"url": url})

        async def _handle_launch_app(call: ServiceCall) -> None:
            app_id = call.data["app_id"]
            for entry_data in hass.data[DOMAIN].values():
                await entry_data["api"].send_action("launch_app", {"app_id": app_id})

        async def _handle_load_youtube(call: ServiceCall) -> None:
            video_id = call.data["video_id"]
            for entry_data in hass.data[DOMAIN].values():
                await entry_data["api"].send_action("load_youtube", {"video_id": video_id})

        hass.services.async_register(
            DOMAIN, SERVICE_LOAD_WEBSITE, _handle_load_website, schema=SERVICE_LOAD_WEBSITE_SCHEMA
        )
        hass.services.async_register(
            DOMAIN, SERVICE_LAUNCH_APP, _handle_launch_app, schema=SERVICE_LAUNCH_APP_SCHEMA
        )
        hass.services.async_register(
            DOMAIN, SERVICE_LOAD_YOUTUBE, _handle_load_youtube, schema=SERVICE_LOAD_YOUTUBE_SCHEMA
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and close the API session."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id, {})
        api: UniFiDisplayAPI | None = entry_data.get("api")
        if api:
            await api.close()
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_LOAD_WEBSITE)
            hass.services.async_remove(DOMAIN, SERVICE_LAUNCH_APP)
            hass.services.async_remove(DOMAIN, SERVICE_LOAD_YOUTUBE)
    return unload_ok

