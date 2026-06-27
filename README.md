# UniFi Protect Presence — Home Assistant Add-on

Bridges **UniFi Protect → MQTT** for two private-API signals the bundled `unifiprotect`
integration can't surface:

1. **Recognized-face smart-detect events** — the matched person *name* (not just "a face").
2. **USL-Environmental leak state** — external-leak detection.

## Why an add-on (not a custom integration)

Home Assistant's bundled `unifiprotect` pins `uiprotect` in core's single shared Python
env, and the recognized face **name** + external-leak fields are private-API — exposed
only via `event.raw` / raw Sensor fields, via the **`subscribe_websocket`** path (the typed
`subscribe_events` path needs an API key and *drops* face identity). An add-on is a separate
container with its own env, so it pins the latest `uiprotect` and reads `event.raw` without
touching core's pinned version. Version-proof; survives HA updates.

## Install

1. Settings → Add-ons → Add-on Store → ⋮ → **Repositories** → add
   `https://github.com/terafin/addon-unifi-protect-presence`.
2. Install **UniFi Protect Presence**, set the options (NVR host/port/user/**password**,
   `verify_ssl`, `base_topic`, `log_level`), start it. MQTT broker creds are taken from
   Supervisor automatically (`mqtt:need`) — nothing to configure there.

## MQTT contract (what HA consumes)

- **Availability** (LWT, retained): `<base_topic>/status` = `online` / `offline`.
- **Face**: `<base_topic>/face`, JSON `{"name","camera","score","ts"}`, published once per
  recognized-face event **only when a name matched**.
- **Leak**: MQTT discovery (retained) to
  `homeassistant/binary_sensor/uipp_<sensor_id>_leak/config` (`device_class: moisture`),
  state on `<base_topic>/leak/<sensor_id>` = `ON`/`OFF`.

`base_topic` defaults to `unifi-protect-presence`.

## Status: v0.1 (live-tuning)

The face-name and leak `raw` paths are private/undocumented. v0.1 extracts them
**defensively** and, at `log_level: debug`, **dumps the full raw** of every smart-detect
event and Sensor delta so the exact paths can be confirmed against live data and finalized.
Spots pending live confirmation are marked `# FINALIZE:` in `run.py`.

License: MIT.
