"""Sensor platform for UniFi Connect Display."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import CONF_DEVICE_ID, DOMAIN, MANUFACTURER, NAME, SENSOR_TYPES

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Connect Display sensor entities from a config entry."""
    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    device_id: str = entry.data[CONF_DEVICE_ID]

    async_add_entities(
        UniFiDisplaySensor(coordinator, entry, device_id, sensor_key)
        for sensor_key in SENSOR_TYPES
    )


class UniFiDisplaySensor(CoordinatorEntity, SensorEntity):
    """A sensor that reports a single status field from the display."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        device_id: str,
        sensor_key: str,
    ) -> None:
        """Initialise the sensor."""
        super().__init__(coordinator)
        friendly_name, unit = SENSOR_TYPES[sensor_key]
        self._sensor_key = sensor_key
        self._attr_name = f"{NAME} {friendly_name}"
        self._attr_unique_id = f"{device_id}_{sensor_key}"
        self._attr_native_unit_of_measurement = unit
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=entry.title,
            manufacturer=MANUFACTURER,
        )

    @property
    def native_value(self) -> Any:
        """Return the sensor value from coordinator data."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.get(self._sensor_key)

