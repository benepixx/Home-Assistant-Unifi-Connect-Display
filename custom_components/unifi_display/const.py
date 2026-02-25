# const.py - Constants for the UniFi Connect Display integration

DOMAIN = "unifi_display"
NAME = "UniFi Connect Display"
MANUFACTURER = "Ubiquiti"

CONF_HOST = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_DEVICE_ID = "device_id"
CONF_VERIFY_SSL = "verify_ssl"

# API paths (host prefix is added at runtime)
API_LOGIN_PATH = "/api/auth/login"
API_DEVICES_PATH = "/proxy/connect/api/v2/devices?shadow=true"
API_DEVICE_PATH = "/proxy/connect/api/v2/devices/{device_id}"
API_DEVICE_STATUS_PATH = "/proxy/connect/api/v2/devices/{device_id}/status"

# Default polling interval (seconds)
DEFAULT_SCAN_INTERVAL = 60

# Actions supported by the display PATCH endpoint
SUPPORTED_ACTIONS = [
    "enable_auto_reload",
    "disable_auto_reload",
    "disable_auto_rotate",
    "load_website",
    "refresh_website",
    "reboot",
    "start_locating",
    "stop_locating",
    "volume",
    "brightness",
    "display_on",
    "display_off",
    "enable_sleep",
    "disable_sleep",
    "enable_memorize_playlist",
    "disable_memorize_playlist",
    "enable_auto_rotate",
    "launch_app",
    "stop_app",
    "load_youtube",
]

# Apps available on the display
AVAILABLE_APPS = [
    "com.ubnt.connect.signage",
    "com.google.android.youtube",
    "com.android.chrome",
    "com.ubnt.connect.home",
]

# Sensor types: key -> (friendly name, unit)
# NOTE: "brightness" and "volume" also appear in number.py as writable controls.
# The sensor entities provide *read-back* of the current device values while the
# number entities provide the slider control interface for setting new values.
SENSOR_TYPES = {
    "brightness": ("Brightness", "%"),
    "volume": ("Volume", "%"),
    "state": ("Display State", None),
    "ip": ("IP Address", None),
    "hostname": ("Hostname", None),
    "resolution": ("Resolution", None),
    "link_quality": ("Link Quality", "%"),
}

# Button actions (single-press, no toggle)
BUTTON_ACTIONS = [
    "display_on",
    "display_off",
    "reboot",
    "start_locating",
    "stop_locating",
    "refresh_website",
]

# Switch action pairs (on_action, off_action, friendly_name)
SWITCH_ACTION_PAIRS = [
    ("enable_auto_reload", "disable_auto_reload", "Auto Reload"),
    ("enable_sleep", "disable_sleep", "Sleep Mode"),
    ("enable_auto_rotate", "disable_auto_rotate", "Auto Rotate"),
    ("enable_memorize_playlist", "disable_memorize_playlist", "Memorize Playlist"),
]

# Service names
SERVICE_LAUNCH_APP = "launch_app"
SERVICE_LOAD_WEBSITE = "load_website"
SERVICE_LOAD_YOUTUBE = "load_youtube"

# Error strings used in config flow
ERROR_CANNOT_CONNECT = "cannot_connect"
ERROR_INVALID_AUTH = "invalid_auth"
ERROR_NO_DEVICES = "no_devices"
ERROR_UNKNOWN = "unknown"

