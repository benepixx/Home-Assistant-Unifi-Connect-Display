# __init__.py - Initializes the UniFi Display integration for Home Assistant

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN

PLATFORMS = ["sensor", "number", "switch", "select", "button"]

async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the UniFi Display component from configuration.yaml (not used)."""
    return True

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up UniFi Display from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Initialize platforms
    await entry.async_setup(hass)
    hass.data[DOMAIN][entry.entry_id] = entry.data

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok

