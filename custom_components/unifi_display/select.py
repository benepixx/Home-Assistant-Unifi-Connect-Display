from homeassistant.components.select import SelectEntity

async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the UniFi Display select options.""" 
    selects = []
    for action in SUPPORTED_ACTIONS:
        selects.append(UniFiDisplaySelect(action))
    async_add_entities(selects)

class UniFiDisplaySelect(SelectEntity):
    """Representation of a UniFi Display Select."""

    def __init__(self, action):
        self._action = action

    @property
    def name(self):
        """Return the name of the select.""" 
        return f"UniFi Display {self._action}"

    async def async_select_option(self, option):
        """Handle the selection.""" 
        # Call API to perform the selected action
        await self._perform_action(option)

    async def _perform_action(self, option):
        """Perform the action using the API.""" 
        pass
