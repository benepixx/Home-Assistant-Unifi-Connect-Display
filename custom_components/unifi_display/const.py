# const.py - Constants and supported configuration

DOMAIN = "unifi_display"
NAME = "UniFi Display"
MANUFACTURER = "Ubiquiti"

CONF_HOST = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"

API_BASE = "/proxy/connect/api/v2"
DEVICE_ENDPOINT = f"{API_BASE}/devices"
STATUS_ENDPOINT = f"{API_BASE}/devices/{{device_id}}/status"  # Corrected line

SUPPORTED_ACTIONS = [
    "enable_auto_reload",
    "disable_auto_reload",
    "disable_auto_rotate",
    "load_website",
    "refresh_website",
    "fw update",
    "reboot",
    "start_locating",
    "stop_locating",
    "volume",
    "brightness",
    "play",
    "stop",
    "display_on",
    "display_off",
    "enable_sleep",
    "disable_sleep",
    "enable_memorize_playlist",
    "disable_memorize_playlist",
    "rotate",
    "enable_auto_rotate",
    "upgrade_mode",
    "launch_app",
    "stop_app",
    "play_layout",
    "signage_screen_fit",
    "switch",
    "load_youtube"
]

AVAILABLE_APPS = [
    "com.unifi.signage",
    "com.google.android.youtube",
    "com.android.chrome",
    "com.ubnt.connect.home"
]

SENSOR_TYPES = {
    "link_quality": ["Link Quality", "%"],
    "brightness": ["Brightness", "level"],
    "volume": ["Volume", "level"],
    "state": ["Display State", None],
    "ip": ["IP Address", None],
    "hostname": ["Hostname", None],
    "resolution": ["Resolution", None]
}

BUTTON_ACTIONS = [
    "display_on",
    "display_off",
    "reboot",
    "start_locating",
    "stop_locating",
    "refresh_website",
    "upgrade_mode"
]

SWITCH_ACTIONS = [
    "enable_auto_reload",
    "disable_auto_reload",
    "enable_sleep",
    "disable_sleep",
    "enable_memorize_playlist",
    "disable_memorize_playlist",
    "enable_auto_rotate",
    "disable_auto_rotate"
]

# Service constants for custom service calls
SERVICE_LAUNCH_APP = "launch_app"
SERVICE_LOAD_WEBSITE = "load_website"
SERVICE_LOAD_YOUTUBE = "load_youtube"

SERVICE_ARGUMENTS = {
    SERVICE_LAUNCH_APP: ["app_id"],
    SERVICE_LOAD_WEBSITE: ["url"],
    SERVICE_LOAD_YOUTUBE: ["video_id"]
}

