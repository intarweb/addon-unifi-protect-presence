ARG BUILD_FROM
# hadolint ignore=DL3006
FROM ${BUILD_FROM}

# uiprotect (latest — the whole point of the add-on: NOT core's pinned version) + paho MQTT.
# The HA base-python image ships pip + bashio; no extra OS packages needed for uiprotect.
# paho-mqtt pinned <2: v0.1 uses the v1 client API (paho 2.x changed the constructor /
# callback-api versioning). Migrate to the v2 API in a later rev if desired.
RUN pip install --no-cache-dir uiprotect "paho-mqtt<2"

COPY run.sh /run.sh
COPY run.py /run.py
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
