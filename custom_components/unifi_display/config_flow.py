import logging
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

class UniFiDisplayConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for UniFi Display."""

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        if user_input is not None:
            # Here you will validate the user_input (host, username, password, etc.)
            # For now we will just store the values
            return self.async_create_entry(
                title=user_input[CONF_HOST], 
                data=user_input
            )

        return self.async_show_form(
            step_id="user",
            data_schema=self._get_data_schema(),
        )

    def _get_data_schema(self):
        """Return the data schema for the user input."""
        return vol.Schema({
            vol.Required(CONF_HOST): str,
            vol.Required(CONF_USERNAME): str,
            vol.Required(CONF_PASSWORD): str,
        })
