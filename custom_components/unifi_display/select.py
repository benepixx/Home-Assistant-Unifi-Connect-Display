"""Select platform for UniFi Connect Display (app switching)."""
from __future__ import annotations

import logging

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .api import UniFiDisplayAPI
from .const import AVAILABLE_APPS, CONF_DEVICE_ID, DOMAIN, MANUFACTURER, NAME

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Connect Display select entities from a config entry."""
    api: UniFiDisplayAPI = hass.data[DOMAIN][entry.entry_id]["api"]
    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    device_id: str = entry.data[CONF_DEVICE_ID]

    async_add_entities([UniFiDisplayAppSelect(api, coordinator, entry, device_id)])


class UniFiDisplayAppSelect(CoordinatorEntity, SelectEntity):
    """A select entity that launches apps on the display."""

    def __init__(
        self,
        api: UniFiDisplayAPI,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
    ) -> None:
        """Initialise the app selector."""
        super().__init__(coordinator)
        self._api = api
        self._attr_name = f"{NAME} Active App"
        self._attr_unique_id = f"{device_id}_app_select"
        self._attr_options = AVAILABLE_APPS
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=entry.title,
            manufacturer=MANUFACTURER,
        )

    @property
    def current_option(self) -> str | None:
        """Return the currently active app from coordinator data."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.get("current_app")

    async def async_select_option(self, option: str) -> None:
        """Launch the selected app on the display."""
        success = await self._api.send_action("launch_app", {"apkId": option})
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to launch app '%s' on display", option)

