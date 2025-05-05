from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_USERNAME, CONF_PASSWORD
from .const import DOMAIN
import aiohttp
import asyncio

class UniFiDisplayConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for UniFi Display."""
    
    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step of the config flow."""
        if user_input is None:
            return self.async_show_form(
                step_id="user",
                data_schema=self._get_data_schema(),
            )

        # Collect user input
        host = user_input[CONF_HOST]
        username = user_input[CONF_USERNAME]
        password = user_input[CONF_PASSWORD]

        # Perform API check (this can be modified based on your API call)
        try:
            async with aiohttp.ClientSession() as session:
                # Replace this with your actual API request
                response = await session.get(f"http://{host}/api/v2/status")
                data = await response.json()
                if response.status != 200:
                    raise ValueError("Unable to connect to UniFi Display")

        except Exception as e:
            return self.async_show_form(
                step_id="user",
                data_schema=self._get_data_schema(),
                errors={"base": str(e)},
            )

        # If no errors, continue with config entry
        return self.async_create_entry(
            title=f"UniFi Display {host}",
            data={CONF_HOST: host, CONF_USERNAME: username, CONF_PASSWORD: password},
        )

    def _get_data_schema(self):
        """Return the schema for user input."""
        return vol.Schema({
            vol.Required(CONF_HOST): str,
            vol.Required(CONF_USERNAME): str,
            vol.Required(CONF_PASSWORD): str,
        })
