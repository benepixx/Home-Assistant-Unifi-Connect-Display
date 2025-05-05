from homeassistant.components.number import NumberEntity
from .const import SENSOR_TYPES

async def async_setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the UniFi Display number platform."""
    add_entities([UniFiDisplayNumber(sensor_type) for sensor_type in SENSOR_TYPES])

class UniFiDisplayNumber(NumberEntity):
    def __init__(self, sensor_type):
        self._sensor_type = sensor_type
        self._value = None

    @property
    def name(self):
        return f"UniFi Display {self._sensor_type}"

    @property
    def value(self):
        return self._value

    async def async_set_value(self, value):
        self._value = value
