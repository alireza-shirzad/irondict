use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex}, // Added Arc and Mutex
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
    structs::pp::IronPublicParameters, // Ensure this path is correct for your project
    structs::{IronLabel, IronSpecification},
};
use iron_key_bench::KZH_PARAM;
use once_cell::sync::Lazy; // Added Lazy
use subroutines::pcs::kzhk::KZHK;

// Type alias for the Public Parameters
type AppPublicParameters = IronPublicParameters<Bn254, KZHK<Bn254>>;

// Static cache for public parameters, keyed by log_capacity (u64)
static PP_CACHE: Lazy<Mutex<HashMap<u64, Arc<AppPublicParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Helper function to get or create PP for a given log_capacity
fn get_or_create_pp(log_capacity: usize) -> Arc<AppPublicParameters> {
    let mut cache = PP_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry(log_capacity.try_into().unwrap())
        .or_insert_with(|| {
            println!(
                "\nCache miss: Creating new IronPublicParameters for log_capacity = {}",
                log_capacity
            );
            let system_spec = IronSpecification::new( 1 << log_capacity, true);
            let pp = IronKey::<Bn254, KZHK<Bn254>, IronLabel>::setup(system_spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

/// Triplet carried around by Divan.
#[derive(Copy, Clone, Debug)]
struct Params(
    pub usize, // log_capacity
    pub usize, // log_update_size
    pub usize, // initial_batch_size
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

/// Builds a server, a warm-up batch of `initial_batch_size`,
/// and the real update batch of size `2^log_update_size`.
/// This function now uses the PP cache.
fn prepare_prover_update_prove_inputs(
    log_capacity: usize,
    log_update_size: usize,
    log_initial_batch_size: usize,
) -> (
    IronServer<Bn254, KZHK<Bn254>, IronLabel>,
    HashMap<IronLabel, Fr>,
    DummyBB<Bn254, KZHK<Bn254>>,
) {
    let initial_batch_size_val = 1 << log_initial_batch_size; // Renamed to avoid conflict if log_initial_batch_size was 0
    // Get PP from cache or create it if it's not there for the given log_capacity
    let pp_arc = get_or_create_pp(log_capacity);
    // Initialize server with the (potentially cached) public parameters
    let mut server: IronServer<_, _, _> = IronServer::init(&*pp_arc); // Dereference Arc
    let mut bulletin_board = DummyBB::default();
    // Warm-up batch just to create the path in the tree.
    let initial_batch: HashMap<_, _> = (1..=initial_batch_size_val)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();

    if initial_batch_size_val > 0 {
        // Only update if there's an initial batch
        server
            .update_reg(&initial_batch, &mut bulletin_board) // Assuming update_reg for warm-up
            .unwrap();
    }

    // Batch whose size we actually benchmark.
    let update_batch_size = 1 << log_update_size;
    let update_batch: HashMap<_, _> = (1..=update_batch_size)
        .map(|i| {
            (
                IronLabel::new(&(i + initial_batch_size_val).to_string()), // Ensure unique labels
                Fr::from(i + initial_batch_size_val),
            )
        })
        .collect();

    (server, update_batch, bulletin_board)
}

/// Compile-time list of (log_capacity, log_update_size) triplets.
pub const PARAMS: &[Params] = &{
    const INIT: usize = 2; // log_initial_batch_size
    // Calculation for array size:
    // The outer loop for n (log_capacity) runs from 20 to 32.
    // The inner loop for k (log_update_size) runs from 0 to n-2.
    // The number of iterations is the sum of (n-1) for n from 20 to 32.
    // Sum = (19 + 20 + ... + 31) = 13 * (19 + 31) / 2 = 325.
    const PARAMS_ARRAY_SIZE: usize = 32;

    const fn build_params() -> [Params; PARAMS_ARRAY_SIZE] {
        let mut out = [Params(4, 0, 2); PARAMS_ARRAY_SIZE];
        let mut i: usize = 0;

        let mut n: usize = 32; // log_capacity starts from 20
        while n <= 32 {
            let mut k = 1; // log_update_size
            while k <= n - 2 {
                if i < PARAMS_ARRAY_SIZE {
                    out[i] = Params(n, k, INIT);
                }
                i += 1;
                k += 1;
            }
            n += 1;
        }
        out
    }
    build_params()
};

#[divan::bench(
    max_time     = 10,
    sample_count = 1,
    sample_size  = 1,
    args         = PARAMS
)]
fn light_update_reg(bencher: Bencher, Params(cap, _upd_log_size, init): Params) {
    // _upd_log_size is passed to prepare_prover_update_prove_inputs,
    // where it's used to determine the size of `update_batch`.
    // The benchmark itself uses this `update_batch`.
    let (mut server, update_batch, mut bb) =
        prepare_prover_update_prove_inputs(cap, _upd_log_size, init);

    let bb_in_size = bb.serialized_size(ark_serialize::Compress::Yes);
    bencher.bench_local(|| {
        // This benchmarks the update_reg with the `update_batch`
        // whose size is determined by `_upd_log_size`.
        server.update_reg(&update_batch, &mut bb).unwrap();
    });
    let bb_out_size = bb.serialized_size(ark_serialize::Compress::Yes);
    println!(
        "Posted bulletin board message size: {} bytes\n",
        bb_out_size - bb_in_size
    );
}
