use ark_bn254::{Bn254 as E, Bn254, Fr};
use divan::Bencher;
use iron_key::{
    VKD,
    VKDAuditor,
    VKDPublicParameters,
    VKDServer, // VKDPublicParameters might be related or an alias
    auditor::IronAuditor,
    bb::dummybb::DummyBB,
    ironkey::IronKey, // For IronKey::setup
    server::IronServer,
    structs::pp::IronPublicParameters, // Crucial import for the actual PP type
    structs::{IronLabel, IronSpecification},
};
use iron_key_bench::KZH_PARAM;
use once_cell::sync::Lazy; // For caching
use std::{
    collections::HashMap,
    sync::{Arc, Mutex}, // For caching
};
use subroutines::pcs::kzhk::KZHK;

// Type alias for the Public Parameters
type AppPublicParameters = IronPublicParameters<E, KZHK<E>>;

// Static cache for public parameters, keyed by log_capacity (u64)
static PP_CACHE: Lazy<Mutex<HashMap<u64, Arc<AppPublicParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
/// Helper function to get or create AppPublicParameters for a given
/// log_capacity
fn get_or_create_pp(log_capacity: u64) -> Arc<AppPublicParameters> {
    let mut cache = PP_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry(log_capacity)
        .or_insert_with(|| {
            println!(
                "\nCache miss: Creating new IronPublicParameters for log_capacity = {}",
                log_capacity
            );
            let spec = IronSpecification::new(1usize << log_capacity, true);
            // IronKey::<..., IronLabel> specifies generics for the IronKey struct itself,
            // its `setup` method returns Result<IronPublicParameters<E, Pcs>, _>
            let pp = IronKey::<Bn254, KZHK<Bn254>, IronLabel>::setup(spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

fn prepare_verifier_lookup_intput(
    // Renaming to prepare_audit_input might be more descriptive
    log_capacity: u64,
    log_first_batch_size: u64,
    log_second_batch_size: u64,
) -> (IronAuditor<E, IronLabel, KZHK<E>>, DummyBB<E, KZHK<E>>) {
    // Get PP from cache or create it if it's not there for the given log_capacity
    let pp_arc = get_or_create_pp(log_capacity);
    let pp_ref = &*pp_arc; // pp_ref is &AppPublicParameters

    let mut server = IronServer::<Bn254, KZHK<Bn254>, IronLabel>::init(pp_ref);
    let mut bulletin_board = DummyBB::default();
    let first_batch_size = 1usize << log_first_batch_size;
    let second_batch_elements = 1usize << log_second_batch_size; // Number of elements in the second batch

    // Build first batch
    let updates1: HashMap<IronLabel, Fr> = (1..=first_batch_size)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();

    if first_batch_size > 0 {
        server.update_reg(&updates1, &mut bulletin_board).unwrap();
        server.update_keys(&updates1, &mut bulletin_board).unwrap();
    }

    // Build second batch, ensuring labels are distinct from the first batch
    // The original range `((first_batch_size + 1)..=(second_batch_size + 1))`
    // with log_second_batch_size=2 (so second_batch_size=4) would be
    // `(4+1)..=(4+1)` => `5..=5`. If the intention is a second batch of
    // `second_batch_elements` items:
    let updates2: HashMap<IronLabel, Fr> = (1..=second_batch_elements)
        .map(|i_in_batch| {
            let actual_index = first_batch_size + i_in_batch; // Make labels distinct
            (
                IronLabel::new(&actual_index.to_string()),
                Fr::from(actual_index as u64),
            )
        })
        .collect();

    if second_batch_elements > 0 {
        server.update_reg(&updates2, &mut bulletin_board).unwrap();
        server.update_keys(&updates2, &mut bulletin_board).unwrap();
    }

    // Assuming IronPublicParameters (pp_ref) has a method to_auditor_key()
    let auditor_key = pp_ref.to_auditor_key();
    let auditor: IronAuditor<_, _, _> = IronAuditor::init(auditor_key);

    (auditor, bulletin_board)
}

#[divan::bench(max_time     = 1,args = [20,21,22,23,24,25,26,27,28,29,30,31,32])]
fn audit(bencher: Bencher, batch_size: usize) {
    // batch_size here is effectively log_capacity
    let current_log_capacity = batch_size as u64;
    let log_first_batch_size = 2_u64; // e.g., 4 elements
    let log_second_batch_size = 2_u64; // e.g., 4 elements in the second batch

    bencher
        .with_inputs(|| {
            prepare_verifier_lookup_intput(
                // Consider renaming this function if its role is broader
                current_log_capacity,
                log_first_batch_size,
                log_second_batch_size,
            )
        })
        .bench_local_refs(|(auditor, bulletin_board)| {
            // Corrected typo from bulltin_board
            auditor.verify_update(bulletin_board) // Assuming this is the method you want to benchmark
        });
}
