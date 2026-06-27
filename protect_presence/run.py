#!/usr/bin/env python3
"""UniFi Protect Presence — bridge Protect recognized-face events and USL-Environmental
leak state to MQTT, fully event-driven over the Protect websocket.

Why standalone (not the HA `unifiprotect` integration): the recognized face NAME and the
external-leak fields are PRIVATE-API, exposed only in the raw NVR JSON; the bundled
integration pins an older uiprotect in core's shared env.

THE uiprotect GOTCHA (burned 2026-06-27): uiprotect parses every WS packet into pydantic
models that SILENTLY DROP `externalLeakDetectedAt` + `leakSettings` (the external water-probe
fields). So `subscribe_websocket`'s parsed `new_obj`/`changed_data` never show an external
leak — only the onboard-contacts `leakDetectedAt`, which IS modeled, comes through. The raw
NVR payload, however, is still on `WSPacket.data_frame.data` BEFORE uiprotect parses it. So
we tap `Bootstrap.process_ws_packet` to read the raw sensor delta and drive leak state from
it — fully WS, no polling. Faces come from the same WS via the normal parsed callback (event
metadata, incl. the recognized `name`, IS preserved). Full state is seeded once at
startup/reconnect from the raw REST list (deltas only carry changed fields). Perf-safe: the
tap does cheap dict-key checks; only Event frames get face extraction.
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

# uiprotect emits a benign pydantic UserWarning serializing some fields (e.g. an int-typed
# `ratio` arriving as 2.36); the value is still used (home-assistant/core#134280). Silence it.
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
KEEPALIVE_SECONDS = int(os.environ.get("KEEPALIVE_SECONDS", "60"))

MQTT_HOST = os.environ["MQTT_HOST"]
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USERNAME = os.environ.get("MQTT_USERNAME") or None
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD") or None

STATUS_TOPIC = f"{BASE_TOPIC}/status"
FACE_TOPIC = f"{BASE_TOPIC}/face"
DISCOVERY_PREFIX = "homeassistant"
LEAK_FIELDS = ("leakDetectedAt", "externalLeakDetectedAt")

_CAMERA_NAMES: dict[str, str] = {}      # camera id -> friendly name (for faces)
_LEAK_STATE: dict[str, str] = {}        # sensor id -> last published "ON"/"OFF"
_LEAK_RAW: dict[str, dict] = {}         # sensor id -> {leakDetectedAt, externalLeakDetectedAt}
_WS_TAP_INSTALLED = False


# ---------------------------------------------------------------------------
# raw helpers (faces)
# ---------------------------------------------------------------------------
def obj_raw(obj) -> dict:
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


def extract_face(raw: dict):
    """Recognized face = metadata.detectedThumbnails[i] with type=='face' AND a `name`.
    Unknown faces have no `name` -> (None, None), so only recognized people publish."""
    meta = raw.get("metadata") if isinstance(raw, dict) else None
    if isinstance(meta, dict):
        for t in (meta.get("detectedThumbnails") or []):
            if isinstance(t, dict) and t.get("type") == "face" and t.get("name"):
                nm = t.get("name")
                if isinstance(nm, str) and nm.strip().lower() not in ("", "unknown", "none"):
                    return nm, t.get("confidence", t.get("score"))
    return None, None


# ---------------------------------------------------------------------------
# leak helpers
# ---------------------------------------------------------------------------
def is_leak_capable(raw: dict) -> bool:
    # Leak unit = leak detection enabled (onboard contacts and/or external probe). Confirmed
    # live: exactly the 5 "*Leak" units have leakSettings.is{Internal,External}Enabled true.
    ls = raw.get("leakSettings") or {}
    return bool(ls.get("isInternalEnabled") or ls.get("isExternalEnabled"))


def leak_state_from_cache(sid: str) -> str:
    # Wet if either detector has a timestamp; the NVR nulls them when dry (confirmed: onboard
    # contacts cleared to null in ~8s), so non-null == currently wet.
    cur = _LEAK_RAW.get(sid) or {}
    return "ON" if (cur.get("leakDetectedAt") or cur.get("externalLeakDetectedAt")) else "OFF"


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
        "name": None,  # inherit device name -> clean binary_sensor.<sensor>
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
# seed (REST raw — once at startup/reconnect) + WS raw-packet tap (leak) + face callback
# ---------------------------------------------------------------------------
def seed_camera_names(protect: ProtectApiClient):
    cameras = getattr(protect.bootstrap, "cameras", {}) or {}
    for cid, cam in (cameras.items() if hasattr(cameras, "items") else []):
        nm = getattr(cam, "name", None) or obj_raw(cam).get("name")
        if nm:
            _CAMERA_NAMES[str(cid)] = nm
    LOG.info("seeded %d camera name(s)", len(_CAMERA_NAMES))


async def seed_leaks(protect: ProtectApiClient, client: mqtt.Client):
    """Seed leak discovery + current state from the raw REST list (deltas only carry changes)."""
    rows = await protect.api_request_list("sensors")
    n = 0
    for s in rows:
        if not isinstance(s, dict) or not is_leak_capable(s):
            continue
        sid = str(s.get("id") or "")
        if not sid:
            continue
        _LEAK_RAW[sid] = {k: s.get(k) for k in LEAK_FIELDS}
        publish_leak_discovery(client, sid, s.get("name") or f"Sensor {sid}")
        publish_leak_state(client, sid, leak_state_from_cache(sid))
        n += 1
    LOG.info("seeded %d leak sensor(s) from raw REST", n)


def install_ws_tap(protect: ProtectApiClient, client: mqtt.Client):
    """Tap the RAW WS packet so we see leak fields uiprotect's model drops. Class-level,
    once — the bootstrap is a pydantic model (no per-instance attr) and is replaced on
    update()/reconnect, but the class method persists."""
    global _WS_TAP_INSTALLED
    if _WS_TAP_INSTALLED:
        return
    bcls = type(protect.bootstrap)
    orig = bcls.process_ws_packet

    def tapped(self, packet, *a, **k):
        try:
            af = getattr(packet.action_frame, "data", None)
            df = getattr(packet.data_frame, "data", None)
            if (
                isinstance(af, dict) and af.get("modelKey") == "sensor"
                and isinstance(df, dict) and any(f in df for f in LEAK_FIELDS)
            ):
                sid = str(af.get("id") or "")
                if sid and sid in _LEAK_RAW:  # only sensors we seeded as leak-capable
                    _LEAK_RAW[sid].update({f: df[f] for f in LEAK_FIELDS if f in df})
                    publish_leak_state(client, sid, leak_state_from_cache(sid))
        except Exception:  # noqa: BLE001
            LOG.exception("ws leak tap error")
        return orig(self, packet, *a, **k)

    bcls.process_ws_packet = tapped
    _WS_TAP_INSTALLED = True
    LOG.info("installed WS raw-packet leak tap")


def make_face_callback(client: mqtt.Client):
    def callback(msg):
        try:
            obj = getattr(msg, "new_obj", None) or getattr(msg, "old_obj", None)
            if obj is None or "event" not in type(obj).__name__.lower():
                return
            raw = obj_raw(obj)
            name, score = extract_face(raw)
            if name:
                cam_id = str(raw.get("camera") or raw.get("cameraId") or "")
                publish_face(client, name, _CAMERA_NAMES.get(cam_id, cam_id or "unknown"), score)
        except Exception:  # noqa: BLE001
            LOG.exception("face callback error")
    return callback


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
    await seed_leaks(protect, client)       # full leak state (REST raw) on every (re)connect
    install_ws_tap(protect, client)         # leak deltas via raw WS packet
    unsub = protect.subscribe_websocket(make_face_callback(client))  # faces via parsed WS
    LOG.info("subscribed to Protect WS (faces + raw leak tap); fully event-driven")
    try:
        while True:
            await asyncio.sleep(KEEPALIVE_SECONDS)
            await protect.update()  # keep WS/cookie/bootstrap fresh
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
