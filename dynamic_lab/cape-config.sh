#!/usr/bin/env bash

NETWORK_IFACE=eth0
IFACE_IP="$(ip -4 -o addr show dev eth0 | awk '{split($4,a,"/"); print a[1]; exit}')"
PASSWD="${CAPE_DB_PASSWORD:?CAPE_DB_PASSWORD must be set}"
USER=cape
CAPE_ROOT=/home/cape/CAPEv2
USE_UV=true
MONGO_ENABLE=1
