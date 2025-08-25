//! msm.rs — simple size-aware MSM wrapper (E: Pairing)
//! - Fixed heuristic thread count (no autotune).
//! - Uses Rayon only if `--features parallel` is enabled; otherwise serial MSM.
//! - 1-term fast path uses direct group scalar multiplication.

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;

use ark_ec::PrimeGroup;
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
// ===============================
// Public API (G1 / G2)
// ===============================

pub fn msm_wrapper_g1<E: Pairing>(
    bases: &[<E::G1 as CurveGroup>::Affine],
    scalars: &[E::ScalarField],
) -> E::G1
where
    E::ScalarField: PrimeField,
    <E::G1 as CurveGroup>::Affine: AffineRepr<ScalarField = E::ScalarField, Group = E::G1>,
{
    msm_wrapper_affine::<E, <E::G1 as CurveGroup>::Affine>(bases, scalars)
}

pub fn msm_wrapper_g2<E: Pairing>(
    bases: &[<E::G2 as CurveGroup>::Affine],
    scalars: &[E::ScalarField],
) -> E::G2
where
    E::ScalarField: PrimeField,
    <E::G2 as CurveGroup>::Affine: AffineRepr<ScalarField = E::ScalarField, Group = E::G2>,
{
    msm_wrapper_affine::<E, <E::G2 as CurveGroup>::Affine>(bases, scalars)
}

// ===============================
// Core wrapper (generic Affine)
// ===============================

pub fn msm_wrapper_affine<E, A>(bases: &[A], scalars: &[E::ScalarField]) -> A::Group
where
    E: Pairing,
    E::ScalarField: PrimeField,
    A: AffineRepr<ScalarField = E::ScalarField>,
    A::Group: VariableBaseMSM,
{
    // Length check matches arkworks' msm API
    if bases.len() != scalars.len() {
        panic!()
    }

    // 1-term fast path: avoid MSM overhead
    if bases.len() == 1 {
        let g = bases[0].into_group();
        return g.mul_bigint(scalars[0].into_bigint());
    }

    // Non-parallel build: just call arkworks MSM
    #[cfg(not(feature = "parallel"))]
    {
        return <A::Group as VariableBaseMSM>::msm(bases, scalars);
    }

    // Parallel build: run MSM inside a small pool with fixed-heuristic threads
    #[cfg(feature = "parallel")]
    {
        let n = bases.len();
        let phys = detect_cores();
        let threads = threads_for_n(n, phys);

        // If threads == 1, avoid building a pool
        if threads <= 1 {
            return <A::Group as VariableBaseMSM>::msm_unchecked(bases, scalars);
        }

        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("failed to build rayon pool");

        pool.install(|| <A::Group as VariableBaseMSM>::msm_unchecked(bases, scalars))
    }
}

// ===============================
// Fixed heuristic thread picker
// ===============================

#[cfg(feature = "parallel")]
fn threads_for_n(n: usize, phys_cores: usize) -> usize {
    // Keep ~>=128 terms per worker; cap at 16 and by physical cores.
    let t = if n < 32 {
        1
    } else if n < 256 {
        2
    } else if n < 512 {
        16
    } else if n < 4096 {
        32
    } else {
        64
    };
    t.min(phys_cores.max(1))
}

#[cfg(feature = "parallel")]
fn detect_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}
