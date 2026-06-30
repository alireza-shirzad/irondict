#!/bin/bash
# Provision a c3-highmem-176 VM (176 vCPU / 1.41 TB RAM) for the
# irondict log_cap=34 bench. Same Sapphire Rapids family (one Intel gen back from c4) as
# c4-highmem-144-lssd (per-core perf matches; we just drop the
# local-SSD attachment that's been chronically stockout). 1.49 TB
# main RAM accommodates the projected ~2 TB peak for K=11 N=2^34 SRS
# gen with comfortable headroom — no swap required.
#
# c4 requires hyperdisk-balanced boot disks (not pd-ssd).
#
# Run from the irondict workspace root.

set -euo pipefail

PROJECT="${PROJECT:-jbonneau-mwalfish-9a0c}"
ZONE="${ZONE:-us-central1-a}"
NETWORK="${NETWORK:-jbonneau-mwalfish-net}"
SUBNET="${SUBNET:-jbonneau-mwalfish-subnet-01}"
VM="${VM:-irondict-xlarge}"
DISK_SIZE="${DISK_SIZE:-200GB}"  # hyperdisk-balanced; cargo + repo
MACHINE="${MACHINE:-c3-highmem-176}"

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
  --boot-disk-type="hyperdisk-balanced" \
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
