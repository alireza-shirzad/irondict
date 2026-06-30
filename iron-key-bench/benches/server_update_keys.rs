use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use divan::Bencher;
use iron_key::{
    VKD,
    VKDServer,
    bb::dummybb::DummyBB,
    ironkey::IronKey,
    server::IronServer,
    structs::pp::IronPublicParameters,
    structs::{IronLabel, IronSpecification},
};
use once_cell::sync::Lazy;
use subroutines::pcs::kzhk::KZHK;

/// Triplet carried around by Divan.
#[derive(Copy, Clone, Debug)]
struct Params(
    pub u64, // log_capacity
    pub u64, // log_update_size
    pub u64, // log_initial_batch_size
);

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[log(capacity)={}, log(|update|)={}, log(init-update)={}]",
            self.0, self.1, self.2
        )
    }
}

type AppPublicParameters = IronPublicParameters<Bn254, KZHK<Bn254>>;

// Per-capacity PP cache so the bench can sweep multiple log_capacities
// in one run (mirrors the pattern used in audit.rs / client_lookup.rs).
// Building the SRS dominates wall time, so each (log_capacity) entry
// is computed once and reused across every (log_update_size) row that
// uses it.
static PP_CACHE: Lazy<Mutex<HashMap<u64, Arc<AppPublicParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn get_or_create_pp(log_capacity: u64) -> Arc<AppPublicParameters> {
    let mut cache = PP_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry(log_capacity)
        .or_insert_with(|| {
            eprintln!(
                "\nCache miss: Creating new IronPublicParameters for log_capacity = {}",
                log_capacity
            );
            let system_spec = IronSpecification::new(1usize << log_capacity, true);
            let pp = IronKey::<Bn254, KZHK<Bn254>, IronLabel>::setup(system_spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

/// Builds a server, a warm-up batch, and the real update batch.
fn prepare_prover_update_prove_inputs(
    pp: &AppPublicParameters,
    log_update_size: u64,
    log_initial_batch_size: u64,
) -> (
    IronServer<Bn254, KZHK<Bn254>, IronLabel>,
    HashMap<IronLabel, Fr>,
    DummyBB<Bn254, KZHK<Bn254>>,
) {
    let initial_batch_size = 1 << log_initial_batch_size;
    let mut server: IronServer<Bn254, KZHK<Bn254>, IronLabel> = IronServer::init(pp);
    let mut bulletin_board = DummyBB::default();

    // Warm-up batch
    let initial_batch: HashMap<_, _> = (1..=initial_batch_size)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    server
        .update_keys(&initial_batch, &mut bulletin_board)
        .unwrap();

    // Batch whose size we actually benchmark.
    let update_batch: HashMap<_, _> = (1..=(1 << log_update_size))
        .map(|i| {
            (
                IronLabel::new(&(i + initial_batch_size).to_string()),
                Fr::from(i + initial_batch_size),
            )
        })
        .collect();

    (server, update_batch, bulletin_board)
}

/// Compile-time list of (log_capacity, log_update_size) pairs. Sweeps
/// log_update_size for each of three log_capacity points that match
/// the aegon regime sizes: 22 (small), 26 (medium), 32 (large). The
/// update_size range covers the aegon publish_bench batches (small
/// uses 64..2048, large uses 4096..131072).
pub const PARAMS: &[Params] = &{
    const INIT: u64 = 2;
    const LOG_CAPS: [u64; 3] = [22, 28, 34];
    const UPDATE_MIN: u64 = 4;  // log_update_size lower bound (= batch 16)
    const UPDATE_MAX: u64 = 17; // log_update_size upper bound (= batch 131072)
    const ROWS_PER_CAP: usize = (UPDATE_MAX - UPDATE_MIN + 1) as usize;
    const ARRAY_SIZE: usize = LOG_CAPS.len() * ROWS_PER_CAP;

    const fn build_params() -> [Params; ARRAY_SIZE] {
        let mut out = [Params(0, 0, INIT); ARRAY_SIZE];
        let mut i: usize = 0;
        let mut cap_idx: usize = 0;
        while cap_idx < LOG_CAPS.len() {
            let n = LOG_CAPS[cap_idx];
            let mut k = UPDATE_MIN;
            while k <= UPDATE_MAX {
                if i < ARRAY_SIZE {
                    out[i] = Params(n, k, INIT);
                }
                i += 1;
                k += 1;
            }
            cap_idx += 1;
        }
        out
    }
    build_params()
};

#[divan::bench(
    max_time     = 10,
    args         = PARAMS
)]
fn light_update_keys(bencher: Bencher, Params(cap, upd, init): Params) {
    let pp_arc = get_or_create_pp(cap);
    let pp_ref = &*pp_arc;

    let (mut server, update_batch, mut bb) =
        prepare_prover_update_prove_inputs(pp_ref, upd, init);
    let bb_in_size = bb.serialized_size(ark_serialize::Compress::Yes);
    bencher.bench_local(|| {
        server.update_keys(&update_batch, &mut bb).unwrap();
    });

    let bb_out_size = bb.serialized_size(ark_serialize::Compress::Yes);
    println!(
        "Posted bulletin board message size: {} bytes\n",
        bb_out_size - bb_in_size
    );
}
