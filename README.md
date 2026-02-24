# UniFi Connect Display – Home Assistant Integration

A fully functional Home Assistant custom integration for controlling [UniFi Connect Display](https://ui.com/display) devices directly from your Home Assistant instance, without relying on HACS.

---

## Features

| Platform | Entity | Description |
|----------|--------|-------------|
| **Button** | Display On / Off | Turn the screen on or off |
| **Button** | Reboot | Reboot the display |
| **Button** | Start / Stop Locating | Blink the display for identification |
| **Button** | Refresh Website | Reload the currently displayed website |
| **Number** | Brightness | Set screen brightness (0 – 100 %) |
| **Number** | Volume | Set speaker volume (0 – 100 %) |
| **Select** | Active App | Switch between installed apps |
| **Switch** | Auto Reload | Toggle automatic content reload |
| **Switch** | Sleep Mode | Toggle sleep mode |
| **Switch** | Auto Rotate | Toggle screen auto-rotation |
| **Switch** | Memorize Playlist | Toggle playlist memorisation |
| **Sensor** | Display State | Current on/off/sleep state |
| **Sensor** | Brightness / Volume | Read-back of current levels |
| **Sensor** | IP / Hostname / Resolution | Device information |
| **Sensor** | Link Quality | Wi-Fi signal quality |

Custom services are also available for loading arbitrary URLs, YouTube videos, and launching apps by package name.

---

## How it works

The integration authenticates with the **UniFi Network controller** using the same mechanism as the official UniFi app and the included shell scripts:

1. POST credentials to `/api/auth/login` → receive a JWT session cookie (`TOKEN`).
2. Decode the JWT payload (Base64) and extract the `csrfToken` field.
3. Include the session cookie **and** `X-CSRF-Token` header in subsequent requests.
4. Send display actions as `PATCH /proxy/connect/api/v2/devices/{device_id}/status` with a JSON body: `{"id": "<uuid>", "name": "<action>", "args": {...}}`.

No cloud dependency, no HACS required.

---

## Installation

### Manual (recommended for custom integrations)

1. Copy the `custom_components/unifi_display/` directory into your Home Assistant
   `config/custom_components/` folder so the path becomes:
   ```
   config/custom_components/unifi_display/
   ```
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration** and search for
   **UniFi Connect Display**.

---

## Configuration

The integration is fully configured through the Home Assistant UI (no YAML required).

### Step 1 – Controller credentials

| Field | Example | Notes |
|-------|---------|-------|
| **Host** | `192.168.1.1` | IP or hostname of the UniFi controller. `https://` is added automatically. |
| **Username** | `admin` | UniFi controller user |
| **Password** | `password` | UniFi controller password |
| **Verify SSL** | off | Enable only if your controller uses a trusted certificate |

### Step 2 – Select display

If multiple UniFi Connect Displays are found on the controller, a second step lets you choose which one to control. If only one display exists it is selected automatically.

---

## Custom services

These services are callable from automations, scripts and the Developer Tools.

### `unifi_display.unifi_display_load_website`

Load any URL on the display.

```yaml
service: unifi_display.unifi_display_load_website
data:
  url: "https://example.com"
```

### `unifi_display.unifi_display_launch_app`

Launch an app by its Android package name.

```yaml
service: unifi_display.unifi_display_launch_app
data:
  app_id: "com.ubnt.connect.signage"
```

Available apps:
- `com.ubnt.connect.signage` – UniFi Signage
- `com.google.android.youtube` – YouTube
- `com.android.chrome` – Chrome
- `com.ubnt.connect.home` – UniFi Home

### `unifi_display.unifi_display_load_youtube`

Open a YouTube video by its video ID.

```yaml
service: unifi_display.unifi_display_load_youtube
data:
  video_id: "dQw4w9WgXcQ"
```

---

## Shell script workaround

Working shell scripts are available in the `shell_scripts/` directory for use without the integration. Update `UNIFI_HOST`, `USERNAME`, `PASSWORD`, and `DISPLAY_ID` in each script, then reference them from `configuration.yaml`:

```yaml
shell_command:
  unifi_display_off: '/bin/bash /config/scripts/unifi_display_off.sh'
  unifi_display_on: '/bin/bash /config/scripts/unifi_display_on.sh'
  unifi_display_navigate: '/bin/bash /config/scripts/unifi_display_navigate.sh'
```

---

## Running the tests

```bash
pip install pytest pytest-asyncio aiohttp
python -m pytest tests/ -v
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Cannot connect` error during setup | Wrong host or controller unreachable | Check the IP address and that port 443 is open |
| `Invalid authentication` error | Wrong username/password | Verify credentials in the UniFi controller UI |
| `No displays found` error | Display not connected to controller | Check the display is online in the UniFi interface |
| Actions not working | Session expired | Restart Home Assistant to force re-authentication |
| SSL errors | Self-signed certificate | Uncheck *Verify SSL certificate* during setup |
