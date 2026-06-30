#!/bin/bash
# Run all 6 irondict benches at whichever args= the bench files
# currently advertise. Driver tolerates per-bench OOM (|| true) so
# small + medium rows already land in the log even when a bigger arg
# at the end of the list aborts SIGABRT.
set -u
cd "$(dirname "$0")"
mkdir -p bench-results
source ~/.cargo/env
BENCHES=(setup audit client_lookup server_lookup server_update_keys server_update_reg)
for b in "${BENCHES[@]}"; do
  echo "=== $(date -u +%H:%M:%S) | starting $b ==="
  cargo bench -p iron-key-bench --bench bench --features parallel -- "$b" >"bench-results/${b}.log" 2>&1 || true
  echo "=== $(date -u +%H:%M:%S) | $b done ==="
  tail -2 "bench-results/${b}.log"
done
echo === ALL DONE ===
ls -la bench-results/*.log
