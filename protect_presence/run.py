#!/usr/bin/env python3
"""UniFi Protect Presence — bridge Protect recognized-face events and USL-Environmental
leak state to MQTT.

Why standalone (not the HA `unifiprotect` integration): the recognized face NAME and the
external-leak fields are PRIVATE-API, exposed only in the raw NVR JSON. The bundled
integration pins an older uiprotect in core's shared env.

v0.3 leak path = TRUE-RAW POLL. uiprotect's pydantic model SILENTLY DROPS `leakSettings`
and `externalLeakDetectedAt` (the external water-probe fields), so neither the bootstrap
objects nor the WS deltas expose them — a real leak on an external probe is invisible via
the model (burned 2026-06-27: contacts test worked via onboard `leakDetectedAt`, which the
model keeps, but the external water probe set `externalLeakDetectedAt`, which it drops).
So leak state is polled from `api_request_list("sensors")` (the raw NVR JSON) every
POLL_SECONDS. Faces still come over the WS event stream (the event metadata, incl. the
recognized `name`, IS preserved). Perf-safe: WS frames are classified by type first (no
per-frame json.dumps/logging that starved HA in v0.1); the poll is one cheap API call.
"""
import asyncio
import contextlib
import json
import logging
import os
import sys
import warnings
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

# uiprotect parses NVR JSON into pydantic models whose field types don't always match what
# the firmware sends (e.g. an int-typed `ratio` arriving as 2.36). Pydantic emits a benign
# UserWarning on serialization — the value is still used. Known uiprotect/HA-core noise
# (home-assistant/core#134280). Silence it so it doesn't clutter the add-on log.
warnings.filterwarnings("ignore", message="Pydantic serializer warnings")

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
POLL_SECONDS = int(os.environ.get("LEAK_POLL_SECONDS", "15"))

MQTT_HOST = os.environ["MQTT_HOST"]
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USERNAME = os.environ.get("MQTT_USERNAME") or None
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD") or None

STATUS_TOPIC = f"{BASE_TOPIC}/status"
FACE_TOPIC = f"{BASE_TOPIC}/face"
DISCOVERY_PREFIX = "homeassistant"

_CAMERA_NAMES: dict[str, str] = {}   # camera id -> friendly name (for face events)
_LEAK_STATE: dict[str, str] = {}     # sensor id -> last published "ON"/"OFF" (publish on change)


# ---------------------------------------------------------------------------
# raw helpers
# ---------------------------------------------------------------------------
def obj_raw(obj) -> dict:
    """Best-effort raw dict of a uiprotect object (used for WS face events)."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    for attr in ("_raw", "raw"):
        v = getattr(obj, attr, None)
        if isinstance(v, dict):
            return v
    for meth in ("unifi_dict", "model_dump", "dict"):
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
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            yield from deep_find_all(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from deep_find_all(item, key)


def extract_face(raw: dict):
    """Return (name, score) for a RECOGNIZED face, else (None, None).

    Confirmed against live events: a recognized face is
      raw[metadata][detectedThumbnails][i] with type=='face' AND a `name` (+ `confidence`).
    An UNKNOWN face is type=='face' with NO `name` (only `group.id`) -> returns None, so
    only recognized people are published.
    """
    name = score = None
    meta = raw.get("metadata") if isinstance(raw, dict) else None
    if isinstance(meta, dict):
        for t in (meta.get("detectedThumbnails") or []):
            if isinstance(t, dict) and t.get("type") == "face" and t.get("name"):
                name = t.get("name")
                score = t.get("confidence", t.get("score"))
                break
    if isinstance(name, str) and name.strip().lower() in ("", "unknown", "none"):
        name = None
    return name, score


# ---------------------------------------------------------------------------
# leak (from TRUE raw NVR JSON — see module docstring)
# ---------------------------------------------------------------------------
def is_leak_capable(raw: dict) -> bool:
    # A leak unit is one with leak detection actually enabled (onboard contacts and/or an
    # external water probe). Confirmed against live raw: exactly the 5 "*Leak" units have
    # leakSettings.is{Internal,External}Enabled true; doors/windows/climate units do not.
    ls = raw.get("leakSettings") or {}
    return bool(ls.get("isInternalEnabled") or ls.get("isExternalEnabled"))


def leak_state(raw: dict) -> str:
    # Wet if either detector has a timestamp. The NVR NULLS these the moment it dries
    # (confirmed: onboard contacts cleared to null in ~8s), so non-null == currently wet.
    #  - leakDetectedAt:         onboard contacts
    #  - externalLeakDetectedAt: external water probe/cable (uiprotect model drops this)
    if raw.get("leakDetectedAt") or raw.get("externalLeakDetectedAt"):
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
        # name=None -> the entity inherits the device name (the sensor is already named e.g.
        # "Kitchen Leak"), giving a clean binary_sensor.kitchen_leak instead of a tripled id.
        "name": None,
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
# leak poll (TRUE raw) + camera-name seed
# ---------------------------------------------------------------------------
def seed_camera_names(protect: ProtectApiClient):
    cameras = getattr(protect.bootstrap, "cameras", {}) or {}
    for cid, cam in (cameras.items() if hasattr(cameras, "items") else []):
        nm = getattr(cam, "name", None) or obj_raw(cam).get("name")
        if nm:
            _CAMERA_NAMES[str(cid)] = nm
    LOG.info("seeded %d camera name(s)", len(_CAMERA_NAMES))


async def poll_leaks(protect: ProtectApiClient, client: mqtt.Client, seed: bool = False):
    """Fetch the TRUE raw sensor JSON and publish leak discovery/state on change."""
    rows = await protect.api_request_list("sensors")
    n = 0
    for s in rows:
        if not isinstance(s, dict) or not is_leak_capable(s):
            continue
        sid = str(s.get("id") or "")
        if not sid:
            continue
        if seed or sid not in _LEAK_STATE:
            publish_leak_discovery(client, sid, s.get("name") or f"Sensor {sid}")
        publish_leak_state(client, sid, leak_state(s))
        n += 1
    if seed:
        LOG.info("seeded %d leak sensor(s) from true raw", n)


# ---------------------------------------------------------------------------
# WS callback — FACES ONLY (leak is polled; the model can't carry external leak)
# ---------------------------------------------------------------------------
def make_callback(client: mqtt.Client):
    def callback(msg):
        try:
            _handle(client, msg)
        except Exception:  # noqa: BLE001
            LOG.exception("error handling WS message")
    return callback


def _handle(client: mqtt.Client, msg):
    # Classify by the typed object's class name FIRST (cheap). Only Event frames get the
    # (costly) raw extraction; everything else is ignored with no raw work / no logging.
    obj = getattr(msg, "new_obj", None) or getattr(msg, "old_obj", None)
    if obj is None:
        return
    if "event" not in type(obj).__name__.lower():
        return
    raw = obj_raw(obj)
    name, score = extract_face(raw)
    if name:
        cam_id = str(raw.get("camera") or raw.get("cameraId") or "")
        camera = _CAMERA_NAMES.get(cam_id, cam_id or "unknown")
        publish_face(client, name, camera, score)


# ---------------------------------------------------------------------------
# supervised main loop
# ---------------------------------------------------------------------------
async def run_once(client: mqtt.Client):
    protect = ProtectApiClient(
        NVR_HOST, NVR_PORT, NVR_USERNAME, NVR_PASSWORD, verify_ssl=VERIFY_SSL,
    )
    await protect.update()  # bootstrap + open WS
    LOG.info("bootstrapped against %s", NVR_HOST)
    seed_camera_names(protect)
    await poll_leaks(protect, client, seed=True)
    unsub = protect.subscribe_websocket(make_callback(client))
    LOG.info("subscribed to Protect WS (faces); polling leaks every %ds", POLL_SECONDS)
    try:
        i = 0
        while True:
            await asyncio.sleep(POLL_SECONDS)
            i += 1
            try:
                await poll_leaks(protect, client)
            except Exception:  # noqa: BLE001
                LOG.exception("leak poll failed")
            if i % 4 == 0:  # ~every 4*POLL keep WS/cookie/bootstrap fresh
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
    for _noisy in ("uiprotect", "aiohttp", "asyncio", "urllib3", "websockets"):
        logging.getLogger(_noisy).setLevel(logging.WARNING)
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
