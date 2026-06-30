#!/bin/bash
# Provision a c4-highmem-144-lssd VM (144 vCPU / 1.12 TB RAM, 12×375 GB
# local SSDs = 4.5 TB) for irondict's large-regime bench at
# log_capacity=34. The earlier m1-megamem-96 (1.4 TB RAM) OOM'd at
# log_cap=32 K=11; log_cap=34 K=11 is projected to need ~2 TB peak
# RSS. We accept 1.12 TB main RAM here in exchange for being able to
# stripe a multi-TB swap across the local SSDs (post-boot setup);
# local-SSD swap is ~50× slower than RAM but ~50× faster than
# anything network-attached, which matters for a workload that
# touches the SRS in roughly streaming patterns.
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
MACHINE="${MACHINE:-c4-highmem-144-lssd}"

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
