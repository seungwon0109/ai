#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <cape-root> <capture-interface> <guest-name>"
    exit 2
fi

cape_root="$1"
capture_interface="$2"
guest_name="$3"
auxiliary="$cape_root/conf/auxiliary.conf"
hyperv="$cape_root/conf/hyperv.conf"

if [[ ! -f "$auxiliary" ]]; then
    echo "CAPE must be installed before configuring it: $auxiliary is missing."
    exit 1
fi

sed -i -E 's/^evtx = .*/evtx = yes/' "$auxiliary"
sed -i -E 's/^sysmon_windows = .*/sysmon_windows = no/' "$auxiliary"
sed -i -E "s|^interface = .*|interface = $capture_interface|" "$auxiliary"

if [[ ! -f "$hyperv" ]]; then
    cp "$cape_root/conf/default/hyperv.conf.default" "$hyperv"
fi

echo "CAPE EVTX collection enabled."
echo "Sysmon EVTX is collected by the evtx auxiliary."
echo "Set the Hyper-V host, SSH key, guest IP, snapshot and machine label in:"
echo "  $hyperv"
echo "The Windows guest must have Sysmon installed before its Ready snapshot."
