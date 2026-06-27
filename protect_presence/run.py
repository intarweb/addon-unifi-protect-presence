#!/usr/bin/env python3
"""UniFi Protect Presence — bridge Protect recognized-face events and USL-Environmental
leak state to MQTT.

Two private-API facts drive the design (both burned in 2026-06-27):
1. LEAK: uiprotect's pydantic model DROPS `externalLeakDetectedAt`/`leakSettings`, so the
   parsed WS callback never sees external-probe leaks. We tap the RAW WS packet
   (`WSPacket.data_frame.data`, pre-parse) to drive leak state. Fully event-driven, no poll.
2. FACE: the recognized NAME is NEVER pushed over the WS — the WS face thumbnails are always
   `name: None`. UniFi attaches the name to the EVENT RECORD only when recognition finalizes
   (event `end`), retrievable via REST. So: the WS `face` smart-detect is the real-time
   TRIGGER; on it we do a targeted REST `get_events` lookup to read the finalized name,
   dedup by event id, gate on confidence, and publish. REST fires ONLY on WS face activity
   (debounced) — never idle polling.

Perf-safe: the WS tap does cheap dict-key checks (no per-frame json.dumps/logging that
starved HA in v0.1).
"""
import asyncio
import contextlib
import json
import logging
import os
import sys
import time
import warnings
from datetime import datetime, timedelta, timezone

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
FACE_MIN_CONFIDENCE = int(os.environ.get("FACE_MIN_CONFIDENCE", "70"))
FACE_LOOKBACK_SECONDS = int(os.environ.get("FACE_LOOKBACK_SECONDS", "180"))
FACE_WINDOW_SECONDS = int(os.environ.get("FACE_WINDOW_SECONDS", "120"))
FACE_POLL_SECONDS = int(os.environ.get("FACE_POLL_SECONDS", "8"))

MQTT_HOST = os.environ["MQTT_HOST"]
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USERNAME = os.environ.get("MQTT_USERNAME") or None
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD") or None

STATUS_TOPIC = f"{BASE_TOPIC}/status"
FACE_TOPIC = f"{BASE_TOPIC}/face"
DISCOVERY_PREFIX = "homeassistant"
LEAK_FIELDS = ("leakDetectedAt", "externalLeakDetectedAt")

_CAMERA_NAMES: dict[str, str] = {}
_LEAK_STATE: dict[str, str] = {}
_LEAK_RAW: dict[str, dict] = {}
_SEEN_FACE_EVENTS: set[str] = set()   # published recognized-face event ids (dedup)
_WS_TAP_INSTALLED = False
_FACE_ACTIVE_UNTIL = 0.0              # monotonic deadline; a WS face detection opens a REST-lookup window
_PROTECT: ProtectApiClient | None = None
_CLIENT: mqtt.Client | None = None


# ---------------------------------------------------------------------------
# raw helpers
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
    Returns (name, confidence) or (None, None). Unknown faces have no `name`."""
    meta = raw.get("metadata") if isinstance(raw, dict) else None
    if isinstance(meta, dict):
        for t in (meta.get("detectedThumbnails") or []):
            if isinstance(t, dict) and t.get("type") == "face" and t.get("name"):
                nm = t.get("name")
                if isinstance(nm, str) and nm.strip().lower() not in ("", "unknown", "none"):
                    return nm, t.get("confidence", t.get("score"))
    return None, None


# ---------------------------------------------------------------------------
# leak
# ---------------------------------------------------------------------------
def is_leak_capable(raw: dict) -> bool:
    ls = raw.get("leakSettings") or {}
    return bool(ls.get("isInternalEnabled") or ls.get("isExternalEnabled"))


def leak_state_from_cache(sid: str) -> str:
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
    LOG.info("face match -> %s (camera=%s confidence=%s)", name, camera, payload["score"])


# ---------------------------------------------------------------------------
# seed + WS tap + face REST worker
# ---------------------------------------------------------------------------
def seed_camera_names(protect: ProtectApiClient):
    cameras = getattr(protect.bootstrap, "cameras", {}) or {}
    for cid, cam in (cameras.items() if hasattr(cameras, "items") else []):
        nm = getattr(cam, "name", None) or obj_raw(cam).get("name")
        if nm:
            _CAMERA_NAMES[str(cid)] = nm
    LOG.info("seeded %d camera name(s)", len(_CAMERA_NAMES))


async def seed_leaks(protect: ProtectApiClient, client: mqtt.Client):
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
    """Tap the RAW WS packet: drive leak from the raw sensor delta (uiprotect's model drops
    the field), and flip _FACE_PENDING when a `face` smart-detect crosses the WS so the
    REST worker fetches the recognized name. Class-level + once (bootstrap is a pydantic
    model replaced on reconnect; the class method persists)."""
    global _WS_TAP_INSTALLED
    if _WS_TAP_INSTALLED:
        return
    bcls = type(protect.bootstrap)
    orig = bcls.process_ws_packet

    def tapped(self, packet, *a, **k):
        global _FACE_ACTIVE_UNTIL
        try:
            af = getattr(packet.action_frame, "data", None)
            df = getattr(packet.data_frame, "data", None)
            if isinstance(af, dict) and isinstance(df, dict):
                mk = af.get("modelKey")
                if mk == "sensor" and any(f in df for f in LEAK_FIELDS):
                    sid = str(af.get("id") or "")
                    if sid and sid in _LEAK_RAW:
                        _LEAK_RAW[sid].update({f: df[f] for f in LEAK_FIELDS if f in df})
                        publish_leak_state(client, sid, leak_state_from_cache(sid))
                elif mk == "event":
                    sdt = df.get("smartDetectTypes")
                    if sdt and "face" in sdt:
                        # name isn't on the WS + attaches at event-end; open a REST-lookup window
                        _FACE_ACTIVE_UNTIL = time.monotonic() + FACE_WINDOW_SECONDS
        except Exception:  # noqa: BLE001
            LOG.exception("ws tap error")
        return orig(self, packet, *a, **k)

    bcls.process_ws_packet = tapped
    _WS_TAP_INSTALLED = True
    LOG.info("installed WS raw-packet tap (leak deltas + face-detection trigger)")


async def lookup_and_publish_faces(protect: ProtectApiClient, client: mqtt.Client):
    """Read recently-finalized recognized-face events from REST (the only place the name
    lives), publish each new one above the confidence floor, dedup by event id."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(seconds=FACE_LOOKBACK_SECONDS)
    events = await protect.get_events(start=start, end=end, limit=200)
    for e in events:
        r = obj_raw(e)
        eid = str(r.get("id") or "")
        if not eid or eid in _SEEN_FACE_EVENTS:
            continue
        name, conf = extract_face(r)
        if not name:
            continue  # not yet recognized / no name — re-check on next lookup (not marked seen)
        if (conf if isinstance(conf, (int, float)) else 0) < FACE_MIN_CONFIDENCE:
            LOG.info("face %s below confidence floor (%s < %s) — skipped", name, conf, FACE_MIN_CONFIDENCE)
            _SEEN_FACE_EVENTS.add(eid)
            continue
        _SEEN_FACE_EVENTS.add(eid)
        cam = _CAMERA_NAMES.get(str(r.get("camera") or ""), "unknown")
        publish_face(client, name, cam, conf)
    if len(_SEEN_FACE_EVENTS) > 2000:  # bound memory
        for old in list(_SEEN_FACE_EVENTS)[:1000]:
            _SEEN_FACE_EVENTS.discard(old)


async def face_worker():
    """Long-lived: a WS face detection opens a short window during which we poll REST for the
    recognized name (which only attaches at event-end). REST runs ONLY inside that post-
    detection window — never idle polling. Dedup by event id prevents repeats."""
    while True:
        await asyncio.sleep(FACE_POLL_SECONDS)
        if _PROTECT is None or _CLIENT is None or time.monotonic() >= _FACE_ACTIVE_UNTIL:
            continue
        try:
            await lookup_and_publish_faces(_PROTECT, _CLIENT)
        except Exception:  # noqa: BLE001
            LOG.exception("face REST lookup failed")


# ---------------------------------------------------------------------------
# supervised main loop
# ---------------------------------------------------------------------------
async def run_once(client: mqtt.Client):
    global _PROTECT
    protect = ProtectApiClient(
        NVR_HOST, NVR_PORT, NVR_USERNAME, NVR_PASSWORD, verify_ssl=VERIFY_SSL,
    )
    await protect.update()
    LOG.info("bootstrapped against %s", NVR_HOST)
    seed_camera_names(protect)
    await seed_leaks(protect, client)
    install_ws_tap(protect, client)
    _PROTECT = protect
    unsub = protect.subscribe_websocket(lambda m: None)  # keep WS active; tap does the work
    LOG.info("subscribed to Protect WS (raw leak tap + face-detection trigger); REST face lookup armed")
    try:
        while True:
            await asyncio.sleep(KEEPALIVE_SECONDS)
            await protect.update()
    finally:
        _PROTECT = None
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
    global _CLIENT
    client = make_mqtt()
    _CLIENT = client
    asyncio.create_task(face_worker())  # long-lived across reconnects
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
