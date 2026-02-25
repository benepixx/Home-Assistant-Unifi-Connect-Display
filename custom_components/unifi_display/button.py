"""Button platform for UniFi Connect Display."""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import UniFiDisplayAPI
from .const import BUTTON_ACTIONS, CONF_DEVICE_ID, DOMAIN, MANUFACTURER, NAME

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Connect Display button entities from a config entry."""
    api: UniFiDisplayAPI = hass.data[DOMAIN][entry.entry_id]["api"]
    device_id: str = entry.data[CONF_DEVICE_ID]

    async_add_entities(
        UniFiDisplayButton(api, entry, device_id, action)
        for action in BUTTON_ACTIONS
    )


class UniFiDisplayButton(ButtonEntity):
    """A button that triggers a single action on the display."""

    def __init__(
        self,
        api: UniFiDisplayAPI,
        entry: ConfigEntry,
        device_id: str,
        action: str,
    ) -> None:
        """Initialise the button."""
        self._api = api
        self._action = action
        friendly = action.replace("_", " ").title()
        self._attr_name = f"{NAME} {friendly}"
        self._attr_unique_id = f"{device_id}_{action}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=entry.title,
            manufacturer=MANUFACTURER,
        )

    async def async_press(self) -> None:
        """Send the action to the display when the button is pressed."""
        success = await self._api.send_action(self._action)
        if not success:
            _LOGGER.error("Failed to send action '%s' to display", self._action)

    @property
    def available(self) -> bool:
        """Return False when the controller has flagged this action as unsupported."""
        return self._api.is_action_supported(self._action)

