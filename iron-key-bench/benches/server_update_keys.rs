use std::{collections::HashMap, fmt};

use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use divan::Bencher;
use iron_key::{
    VKD,
    VKDServer,
    bb::dummybb::DummyBB,
    ironkey::IronKey, // Assuming IronKey::setup is the correct path
    server::IronServer,
    structs::pp::IronPublicParameters, // Import the correct PP type
    structs::{IronLabel, IronSpecification},
};
use once_cell::sync::Lazy;
use subroutines::pcs::kzhk::KZHK;

const SHARED_LOG_CAPACITY: u64 = 32;
/// Triplet carried around by Divan.
#[derive(Copy, Clone, Debug)]
struct Params(
    pub u64, // log_capacity
    pub u64, // log_update_size
    pub u64, // initial_batch_size
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

// Corrected type alias for the Public Parameters returned by setup and used by
// init
type AppPublicParameters = IronPublicParameters<Bn254, KZHK<Bn254>>;

// Determine the shared log_capacity from your PARAMS definition.

// Lazily initialize PP. It will be computed only once.
// SHARED_PP is now of the type returned by IronKey::setup
static SHARED_PP: Lazy<AppPublicParameters> = Lazy::new(|| {
    eprintln!(
        "\nInitializing SHARED_PP (IronPublicParameters) for log_capacity = {}...\n",
        SHARED_LOG_CAPACITY
    );
    let system_spec = IronSpecification::new(1usize << SHARED_LOG_CAPACITY, true);
    // IronKey::<..., IronLabel> specifies the generics for the IronKey struct
    // itself, its `setup` method then returns Result<IronPublicParameters<E,
    // Pcs>, _>
    IronKey::<Bn254, KZHK<Bn254>, IronLabel>::setup(system_spec)
        .expect("Failed to setup shared IronPublicParameters")
});

/// Builds a server, a warm-up batch, and the real update batch.
/// Now takes a reference to the pre-computed AppPublicParameters.
fn prepare_prover_update_prove_inputs(
    pp: &'static AppPublicParameters, // Use the static reference to the shared public parameters
    _log_capacity: u64,               // Kept for consistency, but actual capacity is from pp
    log_update_size: u64,
    log_initial_batch_size: u64,
) -> (
    IronServer<Bn254, KZHK<Bn254>, IronLabel>,
    HashMap<IronLabel, Fr>,
    DummyBB<Bn254, KZHK<Bn254>>,
) {
    let initial_batch_size = 1 << log_initial_batch_size;
    // IronServer::init expects &IronPublicParameters<E, Pcs>
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

pub const PARAMS: &[Params] = &{
    const INIT: u64 = 2;
    const ARRAY_SIZE: usize = (SHARED_LOG_CAPACITY - 1) as usize;

    const fn build_light() -> [Params; ARRAY_SIZE] {
        let mut out = [Params(32, 1, 1); ARRAY_SIZE];
        let mut i = 20;
        while i < ARRAY_SIZE {
            let k = i as u64;
            out[i] = Params(SHARED_LOG_CAPACITY, k, INIT);
            i += 1;
        }
        out
    }
    build_light()
};

#[divan::bench(
    max_time     = 10,
    args         = PARAMS
)]
fn light_update_keys(bencher: Bencher, Params(cap, upd, init): Params) {
    assert_eq!(
        cap, SHARED_LOG_CAPACITY,
        "Benchmark log_capacity does not match SHARED_PP's log_capacity."
    );

    // Access the shared, lazily-initialized public parameters.
    let pp_ref: &'static AppPublicParameters = &*SHARED_PP;

    let (mut server, update_batch, mut bb) =
        prepare_prover_update_prove_inputs(pp_ref, cap, upd, init);
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
