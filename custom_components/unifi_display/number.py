"""Number platform for UniFi Connect Display (brightness and volume)."""
from __future__ import annotations

import logging

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .api import UniFiDisplayAPI
from .const import CONF_DEVICE_ID, DOMAIN, MANUFACTURER, NAME

_LOGGER = logging.getLogger(__name__)

# (action_name, friendly_name, min, max, step)
NUMBER_CONTROLS = [
    ("brightness", "Brightness", 0, 255, 1),
    ("volume", "Volume", 0, 40, 1),
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Connect Display number entities from a config entry."""
    api: UniFiDisplayAPI = hass.data[DOMAIN][entry.entry_id]["api"]
    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    device_id: str = entry.data[CONF_DEVICE_ID]

    async_add_entities(
        UniFiDisplayNumber(api, coordinator, entry, device_id, *params)
        for params in NUMBER_CONTROLS
    )


class UniFiDisplayNumber(CoordinatorEntity, NumberEntity):
    """A number entity that controls brightness or volume on the display."""

    def __init__(
        self,
        api: UniFiDisplayAPI,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
        action: str,
        friendly_name: str,
        min_value: float,
        max_value: float,
        step: float,
    ) -> None:
        """Initialise the number entity."""
        super().__init__(coordinator)
        self._api = api
        self._action = action
        self._attr_name = f"{NAME} {friendly_name}"
        self._attr_unique_id = f"{device_id}_{action}_control"
        self._attr_native_min_value = min_value
        self._attr_native_max_value = max_value
        self._attr_native_step = step
        self._attr_mode = NumberMode.SLIDER
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=entry.title,
            manufacturer=MANUFACTURER,
        )

    @property
    def native_value(self) -> float | None:
        """Return the current value from coordinator data."""
        if self.coordinator.data is None:
            return None
        raw = self.coordinator.data.get(self._action)
        try:
            return float(raw) if raw is not None else None
        except (ValueError, TypeError):
            return None

    async def async_set_native_value(self, value: float) -> None:
        """Send the new value to the display."""
        success = await self._api.send_action(self._action, {"value": int(value)})
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error(
                "Failed to set %s to %s on display", self._action, int(value)
            )

    @property
    def available(self) -> bool:
        """Return False when the controller has flagged this action as unsupported."""
        return self._api.is_action_supported(self._action)

