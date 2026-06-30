#!/bin/bash
# Runs irondict's 5 VKD benches at log_cap=22 (small) + 26 (medium).
# Each bench's PARAMS still includes log_cap=32 (large), which OOMs on
# commodity hardware after the small+medium rows print — we capture
# the small+medium output before the crash, and run large separately
# on a 1+ TB machine.
#
# Logs go to bench-results/{bench}.log. Run from the workspace root.

set -u
cd "$(dirname "$0")"
mkdir -p bench-results

BENCHES=(audit client_lookup server_lookup server_update_keys server_update_reg)

for b in "${BENCHES[@]}"; do
  echo "=== $(date -u +%H:%M:%S) | starting $b ==="
  # ignore exit code: a non-zero return from the OOM at log_cap=32 is
  # expected here. The valuable small+medium rows are already printed.
  cargo bench -p iron-key-bench --bench bench --features parallel -- "$b" \
    >"bench-results/${b}.log" 2>&1 || true
  echo "=== $(date -u +%H:%M:%S) | $b done (last line follows) ==="
  tail -2 "bench-results/${b}.log"
done

echo
echo "=== ALL DONE ==="
ls -la bench-results/*.log
