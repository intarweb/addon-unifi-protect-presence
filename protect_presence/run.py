#!/usr/bin/env python3
"""UniFi Protect Presence — bridge Protect → MQTT for recognized-face smart-detect
events and USL-Environmental leak state.

Why standalone (not the HA `unifiprotect` integration): the recognized face NAME and
the external-leak fields are PRIVATE-API, exposed only via `event.raw` / raw Sensor
fields. The bundled integration pins an older uiprotect in core's shared env. This
add-on runs its own (latest) uiprotect in an isolated container and uses the private
`subscribe_websocket` path (NOT the typed `subscribe_events`, which needs an API key
and DROPS face identity).

v0.1 is intentionally DEFENSIVE + DEBUG-DUMPING: the exact `raw` paths for face name
and leak state are private/undocumented, so this build walks the structures defensively
and, at log_level=debug, dumps the full raw of every smart-detect event + every Sensor
delta so the live shapes can be confirmed and the extraction finalized. Spots that need
confirming against live data are marked `# FINALIZE:`.
"""
import asyncio
import contextlib
import json
import logging
import os
import sys
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

from uiprotect import ProtectApiClient

LOG = logging.getLogger("protect_presence")

# --- config (from run.sh env) ---
NVR_HOST = os.environ["NVR_HOST"]
NVR_PORT = int(os.environ.get("NVR_PORT", "443"))
NVR_USERNAME = os.environ["NVR_USERNAME"]
NVR_PASSWORD = os.environ["NVR_PASSWORD"]
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() == "true"
BASE_TOPIC = os.environ.get("BASE_TOPIC", "unifi-protect-presence").rstrip("/")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info").upper()

MQTT_HOST = os.environ["MQTT_HOST"]
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USERNAME = os.environ.get("MQTT_USERNAME") or None
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD") or None

STATUS_TOPIC = f"{BASE_TOPIC}/status"
FACE_TOPIC = f"{BASE_TOPIC}/face"
DISCOVERY_PREFIX = "homeassistant"

# FINALIZE: heuristic for leak ON — treat a leak timestamp within this window as "wet".
# The real clear/OFF semantics (does Protect clear the field, or carry a separate state?)
# get confirmed from the debug Sensor dumps against the live USL-Environmental probe.
LEAK_RECENT_SECONDS = 600

# camera id -> name, populated from bootstrap (so face events carry a friendly camera name)
_CAMERA_NAMES: dict[str, str] = {}
# sensor_id -> last published leak state ("ON"/"OFF"), to publish only on change
_LEAK_STATE: dict[str, str] = {}


# ---------------------------------------------------------------------------
# defensive raw helpers
# ---------------------------------------------------------------------------
def obj_raw(obj) -> dict:
    """Best-effort extraction of an object's raw/underlying dict, version-agnostic."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    for attr in ("raw", "_raw"):
        v = getattr(obj, attr, None)
        if isinstance(v, dict):
            return v
    for meth in ("unifi_dict", "dict", "model_dump"):
        fn = getattr(obj, meth, None)
        if callable(fn):
            try:
                v = fn()
                if isinstance(v, dict):
                    return v
            except Exception:  # noqa: BLE001
                pass
    return {}


def deep_find_all(node, key):
    """Yield every value stored under `key` anywhere in a nested dict/list."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            yield from deep_find_all(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from deep_find_all(item, key)


def extract_face(raw: dict):
    """Return (name, score) for a recognized face, or (None, None) if no name matched.

    Known private paths (confirm against live debug dumps):
      raw[metadata][detectedThumbnails][i] where type=='face' -> .name (+ .score/.confidence)
      raw[metadata][group][matchedName]
    Walked defensively so a shape change degrades to 'no match' rather than crashing.
    """
    name = None
    score = None

    meta = raw.get("metadata") if isinstance(raw, dict) else None
    if isinstance(meta, dict):
        thumbs = meta.get("detectedThumbnails")
        if isinstance(thumbs, list):
            for t in thumbs:
                if not isinstance(t, dict):
                    continue
                if t.get("type") == "face" and t.get("name"):
                    name = t.get("name")
                    score = t.get("score", t.get("confidence"))
                    break
        if name is None:
            group = meta.get("group")
            if isinstance(group, dict) and group.get("matchedName"):
                name = group.get("matchedName")

    # last-ditch defensive walk
    if name is None:
        for v in deep_find_all(raw, "matchedName"):
            if v:
                name = v
                break

    # ignore empty / unknown-person sentinels
    if isinstance(name, str) and name.strip().lower() in ("", "unknown", "none"):
        name = None
    return name, score


def parse_ts(v):
    """Protect timestamps are ms-epoch (int) or iso strings; return aware datetime or None."""
    if v in (None, "", 0):
        return None
    try:
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


def is_leak_capable(raw: dict) -> bool:
    keys = ("externalLeakDetectedAt", "leakDetectedAt", "leakSettings")
    return any(k in raw for k in keys) or "LEAK" in json.dumps(raw.get("mountType", "")).upper()


def leak_state(raw: dict) -> str:
    """ON if a leak timestamp is recent, else OFF. FINALIZE against live Sensor dumps."""
    now = datetime.now(timezone.utc)
    for k in ("externalLeakDetectedAt", "leakDetectedAt"):
        ts = parse_ts(raw.get(k))
        if ts and (now - ts).total_seconds() <= LEAK_RECENT_SECONDS:
            return "ON"
    return "OFF"


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------
def make_mqtt() -> mqtt.Client:
    client = mqtt.Client(client_id="unifi-protect-presence", clean_session=True)
    if MQTT_USERNAME:
        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.will_set(STATUS_TOPIC, payload="offline", qos=1, retain=True)
    client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
    client.loop_start()
    client.publish(STATUS_TOPIC, "online", qos=1, retain=True)
    LOG.info("MQTT connected %s:%s; published %s=online", MQTT_HOST, MQTT_PORT, STATUS_TOPIC)
    return client


def publish_leak_discovery(client: mqtt.Client, sensor_id: str, sensor_name: str):
    topic = f"{DISCOVERY_PREFIX}/binary_sensor/uipp_{sensor_id}_leak/config"
    payload = {
        "name": f"{sensor_name} Leak",
        "device_class": "moisture",
        "state_topic": f"{BASE_TOPIC}/leak/{sensor_id}",
        "payload_on": "ON",
        "payload_off": "OFF",
        "availability_topic": STATUS_TOPIC,
        "unique_id": f"uipp_{sensor_id}_leak",
        "device": {
            "identifiers": [f"uipp_{sensor_id}"],
            "name": sensor_name,
            "manufacturer": "Ubiquiti",
            "model": "UniFi Protect Sensor",
            "via_device": "unifi-protect-presence",
        },
    }
    client.publish(topic, json.dumps(payload), qos=1, retain=True)
    LOG.info("published leak discovery for sensor %s (%s)", sensor_id, sensor_name)


def publish_leak_state(client: mqtt.Client, sensor_id: str, state: str):
    if _LEAK_STATE.get(sensor_id) == state:
        return
    _LEAK_STATE[sensor_id] = state
    client.publish(f"{BASE_TOPIC}/leak/{sensor_id}", state, qos=1, retain=True)
    LOG.info("leak %s -> %s", sensor_id, state)


def publish_face(client: mqtt.Client, name: str, camera: str, score):
    payload = {
        "name": name,
        "camera": camera,
        "score": float(score) if isinstance(score, (int, float)) else None,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    client.publish(FACE_TOPIC, json.dumps(payload), qos=1, retain=False)
    LOG.info("face match -> %s (camera=%s score=%s)", name, camera, payload["score"])


# ---------------------------------------------------------------------------
# bootstrap seeding + WS callback
# ---------------------------------------------------------------------------
def seed_from_bootstrap(protect: ProtectApiClient, client: mqtt.Client):
    bootstrap = protect.bootstrap
    cameras = getattr(bootstrap, "cameras", {}) or {}
    for cid, cam in (cameras.items() if hasattr(cameras, "items") else []):
        nm = getattr(cam, "name", None) or obj_raw(cam).get("name")
        if nm:
            _CAMERA_NAMES[str(cid)] = nm
    sensors = getattr(bootstrap, "sensors", {}) or {}
    n = 0
    for sid, sensor in (sensors.items() if hasattr(sensors, "items") else []):
        raw = obj_raw(sensor)
        LOG.debug("bootstrap sensor %s raw: %s", sid, json.dumps(raw, default=str)[:4000])
        if not is_leak_capable(raw):
            continue
        nm = getattr(sensor, "name", None) or raw.get("name") or f"Sensor {sid}"
        publish_leak_discovery(client, str(sid), nm)
        publish_leak_state(client, str(sid), leak_state(raw))
        n += 1
    LOG.info("seeded %d leak-capable sensor(s) from bootstrap; %d camera name(s)", n, len(_CAMERA_NAMES))


def make_callback(client: mqtt.Client):
    def callback(msg):
        try:
            _handle(client, msg)
        except Exception:  # noqa: BLE001
            LOG.exception("error handling WS message")
    return callback


def _handle(client: mqtt.Client, msg):
    # WSSubscriptionMessage shape varies by uiprotect version — dig defensively.
    obj = getattr(msg, "new_obj", None) or getattr(msg, "old_obj", None)
    raw = obj_raw(obj)
    model = (raw.get("modelKey") or getattr(obj, "model", None) or "").lower() if raw or obj else ""
    otype = type(obj).__name__.lower() if obj is not None else ""

    # --- smart-detect / face events ---
    if "event" in model or "event" in otype or "smartdetect" in json.dumps(raw)[:200].lower():
        LOG.debug("smart-detect event raw: %s", json.dumps(raw, default=str)[:8000])
        name, score = extract_face(raw)
        if name:
            cam_id = str(raw.get("camera") or raw.get("cameraId") or "")
            camera = _CAMERA_NAMES.get(cam_id, cam_id or "unknown")
            publish_face(client, name, camera, score)
        return

    # --- sensor / leak deltas ---
    if "sensor" in model or "sensor" in otype:
        LOG.debug("sensor delta raw: %s", json.dumps(raw, default=str)[:4000])
        sid = str(raw.get("id") or getattr(obj, "id", "") or "")
        if not sid:
            return
        if is_leak_capable(raw):
            if sid not in _LEAK_STATE:  # first sight via WS — ensure discovery exists
                nm = raw.get("name") or getattr(obj, "name", None) or f"Sensor {sid}"
                publish_leak_discovery(client, sid, nm)
            publish_leak_state(client, sid, leak_state(raw))
        return

    LOG.debug("ignored WS msg model=%s type=%s", model, otype)


# ---------------------------------------------------------------------------
# supervised main loop
# ---------------------------------------------------------------------------
async def run_once(client: mqtt.Client):
    protect = ProtectApiClient(
        NVR_HOST, NVR_PORT, NVR_USERNAME, NVR_PASSWORD, verify_ssl=VERIFY_SSL,
    )
    await protect.update()  # bootstrap + open WS
    LOG.info("bootstrapped against %s", NVR_HOST)
    seed_from_bootstrap(protect, client)
    unsub = protect.subscribe_websocket(make_callback(client))
    LOG.info("subscribed to Protect websocket; streaming events")
    try:
        # keep alive; periodic update() keeps cookie/bootstrap fresh
        while True:
            await asyncio.sleep(60)
            await protect.update()
    finally:
        with contextlib.suppress(Exception):
            unsub()
        with contextlib.suppress(Exception):
            await protect.close_session()


async def main():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    client = make_mqtt()
    backoff = 5
    while True:
        try:
            await run_once(client)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            LOG.exception("Protect connection failed; reconnecting in %ds", backoff)
            client.publish(STATUS_TOPIC, "offline", qos=1, retain=True)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120)
        else:
            backoff = 5
        finally:
            client.publish(STATUS_TOPIC, "online", qos=1, retain=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
