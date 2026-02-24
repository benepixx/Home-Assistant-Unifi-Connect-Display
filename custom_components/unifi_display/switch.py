"""Switch platform for UniFi Connect Display (toggle actions)."""
from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import UniFiDisplayAPI
from .const import CONF_DEVICE_ID, DOMAIN, MANUFACTURER, NAME, SWITCH_ACTION_PAIRS

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Connect Display switch entities from a config entry."""
    api: UniFiDisplayAPI = hass.data[DOMAIN][entry.entry_id]["api"]
    device_id: str = entry.data[CONF_DEVICE_ID]

    async_add_entities(
        UniFiDisplaySwitch(api, entry, device_id, on_action, off_action, friendly_name)
        for on_action, off_action, friendly_name in SWITCH_ACTION_PAIRS
    )


class UniFiDisplaySwitch(SwitchEntity):
    """A switch that sends enable/disable action pairs to the display."""

    def __init__(
        self,
        api: UniFiDisplayAPI,
        entry: ConfigEntry,
        device_id: str,
        on_action: str,
        off_action: str,
        friendly_name: str,
    ) -> None:
        """Initialise the switch."""
        self._api = api
        self._on_action = on_action
        self._off_action = off_action
        self._attr_name = f"{NAME} {friendly_name}"
        self._attr_unique_id = f"{device_id}_{on_action}"
        self._attr_is_on: bool = False
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=entry.title,
            manufacturer=MANUFACTURER,
        )

    @property
    def is_on(self) -> bool:
        """Return the current state of the switch."""
        return self._attr_is_on

    async def async_turn_on(self, **kwargs) -> None:
        """Send the 'enable' action to the display."""
        success = await self._api.send_action(self._on_action)
        if success:
            self._attr_is_on = True
            self.async_write_ha_state()
        else:
            _LOGGER.error(
                "Failed to send action '%s' to display", self._on_action
            )

    async def async_turn_off(self, **kwargs) -> None:
        """Send the 'disable' action to the display."""
        success = await self._api.send_action(self._off_action)
        if success:
            self._attr_is_on = False
            self.async_write_ha_state()
        else:
            _LOGGER.error(
                "Failed to send action '%s' to display", self._off_action
            )
