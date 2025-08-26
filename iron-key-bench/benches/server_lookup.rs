use std::{
    collections::HashMap,
    sync::{Arc, Mutex}, // Added Arc and Mutex
};

use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use divan::Bencher;
use iron_key::{
    VKD, // Make sure this import is correct
    VKDServer,
    bb::dummybb::DummyBB,
    ironkey::IronKey,
    server::IronServer,
    structs::{IronLabel, IronSpecification, pp::IronPublicParameters},
};
use once_cell::sync::Lazy;
use subroutines::pcs::kzhk::KZHK; // Added Lazy

// Type alias for the Public Parameters
type AppPublicParameters = IronPublicParameters<Bn254, KZHK<Bn254>>;

// Static cache for public parameters, keyed by log_capacity
static PP_CACHE: Lazy<Mutex<HashMap<usize, Arc<AppPublicParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Helper function to get or create PP for a given log_capacity
fn get_or_create_pp(log_capacity: usize) -> Arc<AppPublicParameters> {
    let mut cache = PP_CACHE.lock().unwrap_or_else(|e| e.into_inner()); // Handle poisoned mutex if necessary
    cache
        .entry(log_capacity)
        .or_insert_with(|| {
            eprintln!(
                "Cache miss: Creating new IronPublicParameters for log_capacity = {}",
                log_capacity
            );
            let spec = IronSpecification::new(1usize << log_capacity,true);
            let pp = IronKey::<Bn254, KZHK<Bn254>, IronLabel>::setup(spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

/// Build a server that has already processed `batch_size` updates.
fn server_with_updates(
    log_capacity: usize,
) -> (
    IronServer<Bn254, KZHK<Bn254>, IronLabel>,
    DummyBB<Bn254, KZHK<Bn254>>,
    IronLabel,
) {
    let batch_size: usize = 1 << (log_capacity / 2); // This BATCH_SIZE is for the initial updates, not log_capacity
    // Get PP from cache or create it if it's not there for the given log_capacity
    let pp_arc = get_or_create_pp(log_capacity);
    // Initialize server with the (potentially cached) public parameters
    let mut server = IronServer::<Bn254, KZHK<Bn254>, IronLabel>::init(&*pp_arc); // Dereference Arc to get &AppPublicParameters
    let mut bb = DummyBB::default();

    // Build `BATCH_SIZE` distinct (label, value) pairs for initial server state.
    // Note: Using a constant BATCH_SIZE = 1 here for these updates.
    let updates: HashMap<IronLabel, Fr> = (1..=batch_size)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    // // Perform initial updates if required by the benchmark scenario
    // if batch_size > 0 { // Only update if BATCH_SIZE is meaningful
    server.update_reg(&updates, &mut bb).unwrap(); // Assuming update_reg is part of your server's API
    server.update_keys(&updates, &mut bb).unwrap();
    let label = IronLabel::new("1");

    (server, bb, label)
}

/// Benchmark `lookup_prove` after different-sized update batches.
/// The `args` list controls `log_capacity` values.
#[divan::bench(    max_time     = 1,args = [31])]
fn lookup_prove_after_updates(bencher: Bencher, log_capacity_arg: usize) {
    bencher
        // build a brand-new (server, bb, label) for *each* iteration
        .with_inputs(|| {let (server, bb, label) = server_with_updates(log_capacity_arg);
           let proof = server.lookup_prove(label.clone(), &mut bb.clone()).unwrap(); 
            println!("Prepared server with updates: {:?}", proof.get_label_opening_proof().serialized_size(ark_serialize::Compress::Yes)+ proof.get_value_opening_proof().serialized_size(ark_serialize::Compress::Yes));
     (server, bb, label)})
        // pass it *by reference* so the tuple itself is not dropped inside the timer
        .bench_local_refs(|(server, bb, label)| {
            server.lookup_prove(label.clone(), bb).unwrap();
        });
        
}
