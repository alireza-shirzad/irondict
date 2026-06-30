mod audit;
mod client_lookup;
mod kzh;
mod kzh_opening;
mod server_lookup;
mod server_update_keys;
mod server_update_reg;
mod setup;
use ark_bn254 as E;
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use divan::{Bencher, black_box};
use sha2::{Digest, Sha256};
fn sample_msm_inputs(n: usize, seed: u64) -> (Vec<G1Affine>, Vec<Fr>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let bases: Vec<G1Affine> = (0..n)
        .map(|_| G1Projective::rand(&mut rng).into_affine())
        .collect();
    let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    (bases, scalars)
}

/// Measure E::G1::msm with `n` bases/scalars.
/// Try sizes that are big enough to be meaningful but won’t OOM.
#[divan::bench(args = [32,64,128,256, 512, 1024, 2048, 4096, 8192])]
fn msm_g1(bencher: Bencher, n: usize) {
    let (bases, scalars) = sample_msm_inputs(n, 42);

    // Bench just the MSM (no allocation or RNG inside the timing loop).
    bencher.bench_local(|| {
        let res = <G1Projective as VariableBaseMSM>::msm(black_box(&bases), black_box(&scalars));
        black_box(res)
    });
}

#[divan::bench]
fn field_multiplication(bencher: Bencher) {
    let mut rng = ark_std::test_rng();

    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    bencher.bench(|| {
        let mut res = a;
        res *= b;
        res
    });
}

#[divan::bench]
fn sha256_hash(bencher: Bencher) {
    let mut rng = ark_std::test_rng();
    let x = Fr::rand(&mut rng);
    let x_bytes = x.into_bigint().to_bytes_le(); // Convert field element to little-endian bytes
    bencher.bench(|| {
        let mut hasher = Sha256::new();
        hasher.update(&x_bytes);
        hasher.finalize()
    });
}
#[divan::bench]
fn zk(bencher: Bencher) {
    let mut rng = ark_std::test_rng();
    let num = 4096;
    let scalars = (0..num).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let bases = (0..num)
        .map(|_| E::G1Affine::rand(&mut rng))
        .collect::<Vec<_>>();
    bencher.bench(|| <E::G1Projective as VariableBaseMSM>::msm(&bases, &scalars));
}

#[cfg(feature = "parallel")]
pub fn init_rayon_global(threads: usize, stack_bytes: usize) {
    use rayon::ThreadPoolBuilder;
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // choose a sane cap: physical cores or lower on memory‑tight boxes
        let _ = ThreadPoolBuilder::new()
            .num_threads(threads.max(1))
            .stack_size(stack_bytes) // e.g., 2 * 1024 * 1024
            .build_global();
    });
}

fn main() {
    divan::Divan::from_args().main();
}
