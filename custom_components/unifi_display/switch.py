"""Switch platform for UniFi Connect Display (toggle actions)."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .api import UniFiDisplayAPI
from .const import CONF_DEVICE_ID, DOMAIN, MANUFACTURER, NAME, SWITCH_ACTION_PAIRS

_LOGGER = logging.getLogger(__name__)

# Maps on_action name → coordinator data key that reflects the current state.
STATE_KEY_MAP: dict[str, str] = {
    "enable_sleep": "sleep_mode",
    "enable_auto_reload": "auto_reload",
    "enable_auto_rotate": "auto_rotate",
    "enable_memorize_playlist": "memorize_playlist",
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Connect Display switch entities from a config entry."""
    api: UniFiDisplayAPI = hass.data[DOMAIN][entry.entry_id]["api"]
    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    device_id: str = entry.data[CONF_DEVICE_ID]

    entities: list[SwitchEntity] = [
        UniFiDisplayPowerSwitch(api, coordinator, entry, device_id),
    ]
    entities.extend(
        UniFiDisplaySwitch(api, coordinator, entry, device_id, on_action, off_action, friendly_name)
        for on_action, off_action, friendly_name in SWITCH_ACTION_PAIRS
    )
    async_add_entities(entities)


class UniFiDisplayPowerSwitch(CoordinatorEntity, SwitchEntity):
    """Switch that controls display power (on/off) and reflects device state."""

    def __init__(
        self,
        api: UniFiDisplayAPI,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
    ) -> None:
        """Initialise the power switch."""
        super().__init__(coordinator)
        self._api = api
        self._attr_name = f"{NAME} Display Power"
        self._attr_unique_id = f"{device_id}_display_power"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=entry.title,
            manufacturer=MANUFACTURER,
        )

    @property
    def is_on(self) -> bool | None:
        """Return the current display power state from coordinator data."""
        if self.coordinator.data is None:
            return None
        display_on = self.coordinator.data.get("display_on")
        if display_on is None:
            return None
        return bool(display_on)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Send the display_on action."""
        success = await self._api.send_action("display_on")
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to send action 'display_on' to display")

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Send the display_off action."""
        success = await self._api.send_action("display_off")
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to send action 'display_off' to display")


class UniFiDisplaySwitch(CoordinatorEntity, SwitchEntity):
    """A switch that sends enable/disable action pairs to the display."""

    def __init__(
        self,
        api: UniFiDisplayAPI,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
        on_action: str,
        off_action: str,
        friendly_name: str,
    ) -> None:
        """Initialise the switch."""
        super().__init__(coordinator)
        self._api = api
        self._on_action = on_action
        self._off_action = off_action
        self._state_key = STATE_KEY_MAP.get(on_action)
        self._attr_name = f"{NAME} {friendly_name}"
        self._attr_unique_id = f"{device_id}_{on_action}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=entry.title,
            manufacturer=MANUFACTURER,
        )

    @property
    def is_on(self) -> bool | None:
        """Return the current state from coordinator data.

        Returns None (unknown) if no coordinator data or if this switch
        action has no corresponding state key in STATE_KEY_MAP.
        """
        if self._state_key is None or self.coordinator.data is None:
            return None
        value = self.coordinator.data.get(self._state_key)
        if value is None:
            return None
        return bool(value)

    @property
    def available(self) -> bool:
        """Return False when the controller has flagged either action as unsupported."""
        return (
            self._api.is_action_supported(self._on_action)
            and self._api.is_action_supported(self._off_action)
        )

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Send the 'enable' action to the display."""
        success = await self._api.send_action(self._on_action)
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error(
                "Failed to send action '%s' to display", self._on_action
            )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Send the 'disable' action to the display."""
        success = await self._api.send_action(self._off_action)
        if success:
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error(
                "Failed to send action '%s' to display", self._off_action
            )

