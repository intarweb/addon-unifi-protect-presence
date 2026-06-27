# UniFi Protect Presence

Bridges UniFi Protect to MQTT for recognized-face smart-detect events and
USL-Environmental leak state — both private-API signals read from `event.raw` /
raw Sensor fields via the `subscribe_websocket` path.

## Configuration

| Option | Default | Notes |
|---|---|---|
| `nvr_host` | — | NVR hostname/IP (e.g. `unifi.siliconspirit.net`). Required. |
| `nvr_port` | `443` | NVR HTTPS port. |
| `nvr_username` | — | A **local** Protect account (not Ubiquiti SSO). Required. |
| `nvr_password` | — | Password for that account (stored as a secret). Required. |
| `verify_ssl` | `true` | Set `false` only if the NVR uses a self-signed cert. |
| `base_topic` | `unifi-protect-presence` | MQTT topic root. |
| `log_level` | `info` | Set `debug` to dump raw event/Sensor shapes (for tuning). |

MQTT broker credentials are pulled from Supervisor (`mqtt:need`) — do not configure them here.

## What it publishes

- **Availability** (LWT, retained): `<base_topic>/status` = `online`/`offline`.
- **Face** (`<base_topic>/face`): `{"name","camera","score","ts"}` once per recognized-face
  event, only when a name matched.
- **Leak**: auto-discovered `binary_sensor` (`device_class: moisture`); state on
  `<base_topic>/leak/<sensor_id>`.

## Debug / tuning

Set `log_level: debug` to dump the full `raw` of every smart-detect event and Sensor
delta to the add-on log. v0.1 uses defensive extraction with these dumps so the private
`raw` paths (face name, leak timestamps) can be confirmed against your live hardware and
the extraction finalized. The leak ON/OFF heuristic (`LEAK_RECENT_SECONDS`) and the exact
face path are the two `# FINALIZE:` items.
