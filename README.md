#THIS INTEGRATION DOES NOT WORK YET!!!


# UniFi Display Integration for Home Assistant

This integration allows you to control your UniFi Display from Home Assistant.

## Features

- Monitor display status, resolution, brightness, and more.
- Control display actions like turning it on/off, rebooting, and starting locating mode.
- Control display settings like brightness and volume.
- Launch apps and load websites directly on the UniFi Display.
- Custom services for launching apps, loading websites, and YouTube videos.

## Installation

1. Download this repository into the `custom_components/unifi_display/` directory.
2. Restart Home Assistant.
3. Configure the integration by adding the necessary configuration options in Home Assistant's UI or configuration files.

## Supported Actions

- Enable and disable auto reload
- Enable and disable sleep mode
- Enable and disable auto rotate
- Load websites and YouTube videos
- Control volume and brightness

## Configuration

Configure the integration through the Home Assistant UI or YAML configuration.

Example YAML configuration:
```yaml
unifi_display:
  host: "192.168.1.100"
  username: "admin"
  password: "password"
