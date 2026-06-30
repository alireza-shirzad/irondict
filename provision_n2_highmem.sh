#!/bin/bash
# Provision an n2-highmem-16 VM (16 vCPU / 128 GB RAM) for irondict's
# small + medium benches. This is the SAME machine type aegon's
# per-shard cluster bench uses, so setup-time comparisons stay fair
# (the m1-megamem-96 we used before gave irondict an unrealistic 6×
# core advantage, masking its per-vCPU performance).
#
# Memory budget: log_cap=22 K=7 needs ~10 GB peak, log_cap=28 K=9
# needs ~30-50 GB peak — both fit in 64 GB. log_cap=34 absolutely
# does not; that stays on the c4 once it provisions.
#
# Run from the irondict workspace root.

set -euo pipefail

PROJECT="${PROJECT:-jbonneau-mwalfish-9a0c}"
ZONE="${ZONE:-us-central1-a}"
NETWORK="${NETWORK:-jbonneau-mwalfish-net}"
SUBNET="${SUBNET:-jbonneau-mwalfish-subnet-01}"
VM="${VM:-irondict-fair-hm}"
DISK_SIZE="${DISK_SIZE:-200GB}"  # pd-ssd; cargo target + repo + SRS cache
MACHINE="${MACHINE:-n2-highmem-16}"

echo "Creating ${VM} (${MACHINE}) in ${ZONE}..."

gcloud compute instances create "${VM}" \
  --project="${PROJECT}" \
  --zone="${ZONE}" \
  --machine-type="${MACHINE}" \
  --network="${NETWORK}" \
  --subnet="${SUBNET}" \
  --no-address \
  --image-family="ubuntu-2404-lts-amd64" \
  --image-project="ubuntu-os-cloud" \
  --boot-disk-size="${DISK_SIZE}" \
  --boot-disk-type="pd-ssd" \
  --metadata=enable-oslogin=TRUE

echo "Waiting for SSH..."
sleep 30
for i in 1 2 3 4 5 6 7 8 9 10; do
  if gcloud compute ssh "${VM}" --tunnel-through-iap --zone="${ZONE}" --project="${PROJECT}" --command "uptime" 2>/dev/null | grep -q "load average"; then
    break
  fi
  sleep 15
done
echo "SSH ready."
