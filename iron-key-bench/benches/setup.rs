//! Setup (SRS gen) bench for IronKey at the three aegon regime sizes.
//! Measures the wall-clock cost of `IronKey::setup` — dominated by
//! sampling the KZH-k structured reference string.
//!
//! Note: the existing benches cache the SRS file under `srs/` so the
//! second time this is run for a given log_capacity it's just a disk
//! read, not a fresh sample. To measure the prover-side sampling
//! cost, delete `srs/srs_{K}_{log_cap}.bin` before invoking.

use ark_bn254::Bn254;
use divan::Bencher;
use iron_key::{
    VKD,
    ironkey::IronKey,
    structs::{IronLabel, IronSpecification},
};
use subroutines::pcs::kzhk::KZHK;

#[divan::bench(
    max_time     = 60,
    sample_count = 1,
    sample_size  = 1,
    args         = [22, 28, 34],
)]
fn setup(bencher: Bencher, log_capacity: usize) {
    bencher.bench_local(|| {
        let spec = IronSpecification::new(1usize << log_capacity, true);
        IronKey::<Bn254, KZHK<Bn254>, IronLabel>::setup(spec).unwrap()
    });
}
