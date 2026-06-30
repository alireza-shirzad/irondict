#!/bin/bash
# Background retry loop for c4-highmem-144-lssd provisioning.
# Loops across all 4 us-central1 zones with a 90s pause between cycles.
# Stops as soon as one succeeds (sentinel file written).

set -u
PROVISION="/home/alrshir/irondict/provision_c4_xlarge.sh"
LOG="/home/alrshir/irondict/retry_c4.log"
SENTINEL="/home/alrshir/irondict/c4_provisioned.marker"
ZONES=(us-central1-a us-central1-b us-central1-c us-central1-f)

: >"${LOG}"
echo "$(date -u +%H:%M:%S) starting c4 provisioning retry loop" | tee -a "${LOG}"

while true; do
  for z in "${ZONES[@]}"; do
    if [ -f "${SENTINEL}" ]; then exit 0; fi
    echo "$(date -u +%H:%M:%S) attempting ${z}..." | tee -a "${LOG}"
    out=$(ZONE="${z}" bash "${PROVISION}" 2>&1)
    if echo "${out}" | tail -5 | grep -q "SSH ready"; then
      echo "$(date -u +%H:%M:%S) ✓ provisioned in ${z}" | tee -a "${LOG}"
      echo "${z}" >"${SENTINEL}"
      exit 0
    fi
    msg=$(echo "${out}" | grep -E "stockout|resource" | head -1)
    echo "$(date -u +%H:%M:%S)   ${z}: ${msg}" | tee -a "${LOG}"
  done
  sleep 90
done
