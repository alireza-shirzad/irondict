#!/bin/bash
# Install Rust, build irondict, kick off small+medium bench on the
# irondict-fair-hm (n2-standard-16) VM. Idempotent — safe to re-run.

set -euo pipefail

PROJECT=jbonneau-mwalfish-9a0c
ZONE=us-central1-a
VM=irondict-fair-hm

run_remote() {
  gcloud compute ssh "${VM}" --tunnel-through-iap --zone="${ZONE}" --project="${PROJECT}" --command "$1"
}

echo "--- 1) install build deps ---"
run_remote "sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential pkg-config libssl-dev curl git rsync >/dev/null && echo deps_ok"

echo "--- 2) install rustup + nightly-2025-04-03 ---"
run_remote "if [ ! -x ~/.cargo/bin/cargo ]; then curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal; fi; source ~/.cargo/env; rustup toolchain install nightly-2025-04-03 --profile minimal -c rust-src 2>&1 | tail -3; echo rust_ok"

echo "--- 3) rsync irondict to VM (using scp recursive — no rsync on remote) ---"
gcloud compute scp --recurse --tunnel-through-iap --zone="${ZONE}" --project="${PROJECT}" \
  /home/alrshir/irondict/{arithmetic,iron-key,iron-key-bench,subroutines,transcript,util,Cargo.toml,Cargo.lock,rust-toolchain.toml,run_large.sh} "${VM}:~/irondict/" 2>&1 | tail -3

echo "--- 4) trim bench args to [22, 28] (n2 can't fit 34) ---"
run_remote "cd ~/irondict; \
  sed -i 's/args = \[22, 28, 34\]/args = [22, 28]/' iron-key-bench/benches/audit.rs iron-key-bench/benches/client_lookup.rs iron-key-bench/benches/server_lookup.rs; \
  sed -i 's/LOG_CAPS: \[u64; 3\] = \[22, 28, 34\]/LOG_CAPS: [u64; 2] = [22, 28]/' iron-key-bench/benches/server_update_keys.rs; \
  sed -i 's/LOG_CAPS: \[usize; 3\] = \[22, 28, 34\]/LOG_CAPS: [usize; 2] = [22, 28]/' iron-key-bench/benches/server_update_reg.rs; \
  sed -i 's/args         = \[22, 28, 34\],/args         = [22, 28],/' iron-key-bench/benches/setup.rs; \
  sed -i 's/ARRAY_SIZE: usize = LOG_CAPS.len() \* ROWS_PER_CAP;/ARRAY_SIZE: usize = LOG_CAPS.len() * ROWS_PER_CAP;/' iron-key-bench/benches/server_update_keys.rs; \
  grep -E 'args|LOG_CAPS' iron-key-bench/benches/*.rs"

echo "--- 5) build (release) ---"
run_remote "cd ~/irondict; source ~/.cargo/env; cargo build --release -p iron-key-bench --features parallel 2>&1 | tail -5"

echo "--- 6) start driver (nohup) ---"
run_remote "cd ~/irondict; rm -rf bench-results srs; mkdir -p bench-results srs; source ~/.cargo/env; nohup bash run_large.sh > bench-results/driver.out 2>&1 < /dev/null & disown; sleep 3; ps -ef | grep -E 'run_large|cargo bench' | grep -v grep | head"
