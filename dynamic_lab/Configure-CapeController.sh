#!/usr/bin/env bash
set -euo pipefail

CAPE_ROOT="/home/cape/CAPEv2"
CUCKOO_CONF="$CAPE_ROOT/conf/cuckoo.conf"
HYPERV_CONF="$CAPE_ROOT/conf/hyperv.conf"
API_CONF="$CAPE_ROOT/conf/api.conf"
PROCESSING_CONF="$CAPE_ROOT/conf/processing.conf"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RESULTSERVER_PATCH="$SCRIPT_DIR/patches/cape-resultserver-portproxy-alias.patch"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi
if [[ ! -f "$CUCKOO_CONF" || ! -f "$HYPERV_CONF" || ! -f "$API_CONF" || ! -f "$PROCESSING_CONF" ]]; then
    echo "CAPE configuration files were not found under $CAPE_ROOT/conf." >&2
    exit 1
fi
if [[ ! -f "$RESULTSERVER_PATCH" ]]; then
    echo "Required CAPE ResultServer patch was not found: $RESULTSERVER_PATCH" >&2
    exit 1
fi

# Windows portproxy terminates the guest connection and opens a new connection
# from the WSL gateway. Teach the single-VM ResultServer to accept that trusted
# source address for the currently registered task.
if ! grep -q 'self.proxy_source_ip = cfg.resultserver.get("proxy_source_ip")' \
    "$CAPE_ROOT/lib/cuckoo/core/resultserver.py"; then
    patch --batch --forward -d "$CAPE_ROOT" -p1 < "$RESULTSERVER_PATCH"
fi

WSL_GATEWAY="$(ip -4 route show default | awk 'NR == 1 { print $3 }')"
if [[ -z "$WSL_GATEWAY" ]]; then
    echo "Unable to determine the Windows-side WSL gateway address." >&2
    exit 1
fi
crudini --set "$CUCKOO_CONF" resultserver proxy_source_ip "$WSL_GATEWAY"

# CAPE runs inside WSL, whose address can change after a reboot. Binding the
# ResultServer to all WSL interfaces avoids hard-coding that transient address.
sed -i \
    '/^\[resultserver\]/,/^\[/ s/^ip = .*/ip = 0.0.0.0/' \
    "$CUCKOO_CONF"

# The guest reaches the Windows side of the isolated Hyper-V switch. Windows
# forwards this single port to the WSL ResultServer (Start-CapeLab.ps1).
sed -i \
    '/^\[cape-win11\]/,$ s/^[[:space:]]*resultserver_ip[[:space:]]*=.*$//' \
    "$HYPERV_CONF"
sed -i \
    '/^[[:space:]]*arch[[:space:]]*=[[:space:]]*x64[[:space:]]*$/a resultserver_ip = 192.168.56.1' \
    "$HYPERV_CONF"

# Ubuntu packages may install both mongodb.service and mongod.service. Keep the
# service that already owns 127.0.0.1:27017 and disable the duplicate unit.
systemctl disable --now mongod.service 2>/dev/null || true
systemctl enable --now mongodb.service

# Expose only the read-only machine/status endpoints needed by the local
# orchestrator, and require the existing DRF API token for each endpoint.
for section in machinelist machineview cuckoostatus filecreate taskview taskreport; do
    crudini --set "$API_CONF" "$section" enabled yes
    crudini --set "$API_CONF" "$section" auth_only yes
done
# Keep analysis offline and deterministic. External reputation lookups are not
# required for local behavior collection and can delay reports for every file
# extracted by PyInstaller samples.
crudini --set "$PROCESSING_CONF" virustotal enabled no
crudini --set "$PROCESSING_CONF" virustotal do_file_lookup no
crudini --set "$PROCESSING_CONF" virustotal do_url_lookup no

echo "CAPE ResultServer bind: 0.0.0.0:2042"
echo "Guest ResultServer target: 192.168.56.1:2042"
echo "Accepted portproxy source: $WSL_GATEWAY"
echo "MongoDB service: $(systemctl is-active mongodb.service)"
echo "Authenticated machine/status APIs: enabled"
echo "VirusTotal processing lookup: disabled"
