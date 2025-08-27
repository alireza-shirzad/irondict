// benches/akd_bench.rs
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::{Duration, Instant};
use rand::{rngs::StdRng, Rng, SeedableRng};

use akd::storage::StorageManager;
use akd::storage::memory::AsyncInMemoryDatabase;
use akd::ecvrf::HardCodedAkdVRF;
use akd::{AkdLabel, AkdValue, EpochHash, HistoryParams};
use akd::directory::Directory;
use bincode;
use rayon::prelude::*;

type Config = akd::WhatsAppV1Configuration;

// === TUNE THESE ===
const N: usize = 1_000_000_000; // number of initial keys (set to desired N)
const LOOKUP_PROBES: usize = 10; // number of random lookups to benchmark
const UPDATE_ROUNDS: usize = 20; // change one key this many times
const AUDIT_UPDATES: usize = 2000 * 60 * 10; // as you requested (1_200_000)
const RNG_SEED: u64 = 42;
// ===================

fn setup_dir_and_publish(n: usize) -> (Directory<Config, AsyncInMemoryDatabase, HardCodedAkdVRF>, EpochHash, Vec<String>) {
    // Build a tokio Runtime to run async initialization synchronously here
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let db = AsyncInMemoryDatabase::new();
        let storage_manager = StorageManager::new_no_cache(db);
        let vrf = HardCodedAkdVRF {};
        let akd = Directory::<Config, _, _>::new(storage_manager, vrf)
            .await
            .expect("Could not create directory");

        // Generate entries
        let (keys, entries): (Vec<_>, Vec<_>) = (0..n)
            .into_par_iter()
            .map(|i| {
                let key = format!("key_{i}");
                let val = format!("value_{i}");
                (
                    key.clone(),
                    (
                        AkdLabel::from(key.as_str()),
                        AkdValue::from(val.as_str()),
                    ),
                )
            })
            .unzip();


        let epoch_hash = match akd.publish(entries).await {
            Ok(eh) => eh,
            Err(e) => panic!("publish failed: {:?}", e),
        };

        (akd, epoch_hash, keys)
    })
}

fn bench_akd(c: &mut Criterion) {
    // --- Setup once ---
    // For heavy N you may prefer to create directory in a separate machine step.
    // We'll measure operations after the initial publish.
    eprintln!("Setting up directory and publishing N = {N} entries (this may take a while)...");
    let (akd, initial_epoch_hash, keys) = setup_dir_and_publish(N);
    eprintln!("Done initial publish: epoch {:?}", initial_epoch_hash);

    // Make a tokio runtime to use during benchmark iterations
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Prepare deterministic RNG and sample keys for lookup
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let lookup_indices: Vec<usize> = (0..LOOKUP_PROBES).map(|_| rng.gen_range(0..keys.len())).collect();

    // Get VRF public key
    let vrf_public_key = rt.block_on(async { akd.get_public_key().await.expect("get pubkey") });
    let vrf_pub_bytes = vrf_public_key.as_bytes().to_vec();

    // --- Benchmark server lookup (produce proof) ---
    c.bench_function("server_lookup_produce_proof", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                // pick a random key index
                let idx = lookup_indices[usize::wrapping_mul(1, 0) % lookup_indices.len()]; // pick first seed repeatedly to keep deterministic
                let label = AkdLabel::from(keys[idx].as_str());
                let start = Instant::now();
                let _ = rt.block_on(async { akd.lookup(label).await.expect("lookup failed") });
                total += start.elapsed();
            }
            total
        })
    });

    // --- Benchmark client verify for lookups ---
    // We'll get actual proofs once (to avoid including server time in client benchmark)
    let mut lookup_proofs = Vec::with_capacity(lookup_indices.len());
    let mut lookup_epoch_hashes = Vec::with_capacity(lookup_indices.len());
    for &idx in &lookup_indices {
        let (proof, e_hash) = rt.block_on(async { akd.lookup(AkdLabel::from(keys[idx].as_str())).await.expect("lookup") });
        lookup_proofs.push(proof);
        lookup_epoch_hashes.push(e_hash);
    }

    c.bench_function("client_lookup_verify", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for i in 0..iters {
                let j = i as usize % lookup_proofs.len();
                let start = Instant::now();
                // Note: lookup_verify is synchronous in your snippet; if it returns Result, keep it.
                let _ = akd::client::lookup_verify::<Config>(
                    vrf_pub_bytes.as_slice(),
                    lookup_epoch_hashes[j].hash(),
                    lookup_epoch_hashes[j].epoch(),
                    AkdLabel::from(keys[lookup_indices[j]].as_str()),
                    lookup_proofs[j].clone(),
                ).expect("client verify failed");
                total += start.elapsed();
            }
            total
        })
    });

    // --- Update a single key repeatedly and benchmark lookup + verify each time ---
    let target_idx = keys.len() / 2; // pick middle key; change it UPDATE_ROUNDS times
    let target_key = keys[target_idx].clone();

    // apply updates
    let mut last_epoch_hash = initial_epoch_hash.clone();
    for round in 0..UPDATE_ROUNDS {
        let e = rt.block_on(async {
            let entries = vec![(AkdLabel::from(target_key.as_str()), AkdValue::from(format!("value_{}_updated_{}", target_key, round).as_str()))];
            akd.publish(entries).await.expect("update publish failed")
        });
        last_epoch_hash = e;
    }

    // server lookup for updated key benchmark
    c.bench_function("server_lookup_updated_key", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                let _ = rt.block_on(async { akd.lookup(AkdLabel::from(target_key.as_str())).await.expect("lookup updated") });
                total += start.elapsed();
            }
            total
        })
    });

    // client verify for updated key: fetch one proof
    let (updated_proof, updated_epoch_hash) = rt.block_on(async { akd.lookup(AkdLabel::from(target_key.as_str())).await.expect("lookup updated") });

    c.bench_function("client_lookup_updated_key_verify", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                let _ = akd::client::lookup_verify::<Config>(
                    vrf_pub_bytes.as_slice(),
                    updated_epoch_hash.hash(),
                    updated_epoch_hash.epoch(),
                    AkdLabel::from(target_key.as_str()),
                    updated_proof.clone(),
                ).expect("verify updated lookup failed");
                total += start.elapsed();
            }
            total
        })
    });

    // --- Key history: server produce history proof and client verify ---
    // produce history server-side once so we can benchmark produce + verify separately
    c.bench_function("server_history_proof", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                let _ = rt.block_on(async { akd.key_history(&AkdLabel::from(target_key.as_str()), HistoryParams::default()).await.expect("history") });
                total += start.elapsed();
            }
            total
        })
    });

    // get one actual history proof to benchmark client verification
    let (history_proof, history_epoch_hash) = rt.block_on(async { akd.key_history(&AkdLabel::from(target_key.as_str()), HistoryParams::default()).await.expect("history") });

    c.bench_function("client_history_verify", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                let _ = akd::client::key_history_verify::<Config>(
                    vrf_pub_bytes.as_slice(),
                    history_epoch_hash.hash(),
                    history_epoch_hash.epoch(),
                    AkdLabel::from(target_key.as_str()),
                    history_proof.clone(),
                    akd::HistoryVerificationParams::default(),
                ).expect("history verify failed");
                total += start.elapsed();
            }
            total
        })
    });

    // --- AUDIT: append a large batch of new keys/updates and get audit proof ---
    eprintln!("Publishing large AUDIT_UPDATES = {AUDIT_UPDATES} to create audit proof (this may take a while)...");
    // create updates; choose half new keys, half updating existing keys to mimic mixed workload
    let mut audit_entries = Vec::with_capacity(AUDIT_UPDATES);
    for i in 0..AUDIT_UPDATES {
        let key = format!("audit_new_key_{i}");
        let val = format!("audit_val_{}", i);
        audit_entries.push((AkdLabel::from(key.as_str()), AkdValue::from(val.as_str())));
    }

    // measure server time to publish the audit updates and then produce an audit proof between two epochs.
    let (audit_gen_time, audit_proof, root_hash_before, root_hash_after) = {
        // record root hash before publish -- get it from most recent epoch hash
        let root_before = last_epoch_hash.1.clone();

        let start_publish = Instant::now();
        let new_epoch = rt.block_on(async { akd.publish(audit_entries).await.expect("audit publish failed") });
        let publish_dur = start_publish.elapsed();

        // now get audit between previous epoch and the new one
        let start_audit = Instant::now();
        let audit_proof = rt.block_on(async { akd.audit(last_epoch_hash.0, new_epoch.0).await.expect("audit failed") });
        let audit_dur = start_audit.elapsed();

        // total server time we will report = publish_dur + audit_dur (both server-side work)
        (publish_dur + audit_dur, audit_proof, root_before, new_epoch.1)
    };
    eprintln!("Audit generation (publish + audit proof) took: {:?}", audit_gen_time);


    // measure client verification time for audit proof
    let audit_verify_time = {
        let start = Instant::now();
        let fut = akd::auditor::audit_verify::<Config>(vec![root_hash_before.clone(), root_hash_after.clone()], audit_proof.clone());
        // audit_verify in your snippet was async `.await`, so call block_on
        let verified = rt.block_on(fut);
        let dur = start.elapsed();
        if let Err(e) = verified {
            panic!("audit verify failed: {:?}", e);
        }
        dur
    };

    // Print summary measurements (also criterion will have micro-benchmarks above)
    let serialized = bincode::serialize(&audit_proof)
        .expect("Serialization failed");
    println!(
        "Audit proof (serialized size): {} bytes (~{:.2} MB)",
        serialized.len(),
        serialized.len() as f64 / (1024.0 * 1024.0)
    );

    println!("=== Summary (ad-hoc measurements) ===");
    println!("Audit generation time (publish + produce audit proof): {:?}", audit_gen_time);
    println!("Audit verification time (client): {:?}", audit_verify_time);
}

criterion_group!(benches, bench_akd);
criterion_main!(benches);