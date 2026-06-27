#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -e

# --- add-on options ---
NVR_HOST="$(bashio::config 'nvr_host')"
NVR_PORT="$(bashio::config 'nvr_port')"
NVR_USERNAME="$(bashio::config 'nvr_username')"
NVR_PASSWORD="$(bashio::config 'nvr_password')"
VERIFY_SSL="$(bashio::config 'verify_ssl')"
BASE_TOPIC="$(bashio::config 'base_topic')"
LOG_LEVEL="$(bashio::config 'log_level')"
FACE_MIN_CONFIDENCE="$(bashio::config 'face_min_confidence')"

if bashio::var.is_empty "${NVR_HOST}" || bashio::var.is_empty "${NVR_USERNAME}" || bashio::var.is_empty "${NVR_PASSWORD}"; then
  bashio::exit.nok "nvr_host, nvr_username and nvr_password are required in the add-on options."
fi

# --- MQTT credentials from Supervisor (services: mqtt:need) — never hardcode ---
if ! bashio::services.available "mqtt"; then
  bashio::exit.nok "No MQTT service available. Install + start the Mosquitto broker add-on (this add-on declares mqtt:need)."
fi
MQTT_HOST="$(bashio::services 'mqtt' 'host')"
MQTT_PORT="$(bashio::services 'mqtt' 'port')"
MQTT_USERNAME="$(bashio::services 'mqtt' 'username')"
MQTT_PASSWORD="$(bashio::services 'mqtt' 'password')"

export NVR_HOST NVR_PORT NVR_USERNAME NVR_PASSWORD VERIFY_SSL BASE_TOPIC LOG_LEVEL FACE_MIN_CONFIDENCE
export MQTT_HOST MQTT_PORT MQTT_USERNAME MQTT_PASSWORD

bashio::log.info "UniFi Protect Presence → NVR ${NVR_HOST}:${NVR_PORT} (user ${NVR_USERNAME}), MQTT ${MQTT_HOST}:${MQTT_PORT}, base_topic '${BASE_TOPIC}', log_level ${LOG_LEVEL}"

exec python3 -u /run.py
