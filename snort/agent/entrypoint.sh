#!/bin/bash
set -euo pipefail

SNORT_CONF="${SNORT_CONF}"
SNORT_RULES="${SNORT_RULES}"
SNORT_IFACE="${SNORT_IFACE}"
SNORT_LOG="${SNORT_LOG}"

export PYTHONUNBUFFERED=1

mkdir -p /var/run

python3 /opt/snort-agent/agent.py > /proc/1/fd/1 2> /proc/1/fd/2 &

exec snort --daq afpacket -c "$SNORT_CONF" -R "$SNORT_RULES" -i "${SNORT_IFACE}" -l "${SNORT_LOG}" >> /proc/1/fd/1 2>> /proc/1/fd/2
