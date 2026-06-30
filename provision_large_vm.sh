#!/bin/bash
# Provision a c4-highmem-144 VM (144 vCPU / 1.14 TB RAM) for irondict
# large-regime benches (log_capacity=32 only). Uses pd-ssd, no local
# SSDs — irondict reads the SRS file once at startup so disk
# throughput isn't the bottleneck. RAM is the bottleneck.
#
# Requires gcloud CLI configured for the same project as akd-mysql /
# akd-bench. Run from the irondict workspace root.

set -euo pipefail

PROJECT="${PROJECT:-jbonneau-mwalfish-9a0c}"
ZONE="${ZONE:-us-central1-a}"
NETWORK="${NETWORK:-jbonneau-mwalfish-net}"
SUBNET="${SUBNET:-jbonneau-mwalfish-subnet-01}"
VM="${VM:-irondict-large}"
DISK_SIZE="${DISK_SIZE:-200GB}"  # pd-ssd; needs to fit cargo target + srs + repo
MACHINE="${MACHINE:-m1-megamem-96}"

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
