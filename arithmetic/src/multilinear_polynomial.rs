use ark_ff::{Field, PrimeField};
pub use ark_poly::DenseMultilinearExtension;
use ark_poly::{
    univariate::DenseOrSparsePolynomial, MultilinearExtension, SparseMultilinearExtension,
};
use ark_std::{
    cfg_iter, end_timer,
    rand::{Rng, RngCore},
    start_timer, UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use crate::bits_le_to_usize;

/// Sample a random list of multilinear polynomials.
/// Returns
/// - the list of polynomials,
/// - its sum of polynomial evaluations over the boolean hypercube.
pub fn random_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> (Vec<Arc<DenseMultilinearExtension<F>>>, F) {
    let start = start_timer!(|| "sample random mle list");
    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1usize << nv))
    }
    let mut sum = F::zero();

    for _ in 0..(1usize << nv) {
        let mut product = F::one();

        for e in multiplicands.iter_mut() {
            let val = F::rand(rng);
            e.push(val);
            product *= val;
        }
        sum += product;
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();

    end_timer!(start);
    (list, sum)
}

// Build a randomize list of mle-s whose sum is zero.
pub fn random_zero_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let start = start_timer!(|| "sample random zero mle list");

    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1usize << nv))
    }
    for _ in 0..(1usize << nv) {
        multiplicands[0].push(F::zero());
        for e in multiplicands.iter_mut().skip(1) {
            e.push(F::rand(rng));
        }
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();

    end_timer!(start);
    list
}

pub fn identity_permutation<F: PrimeField>(num_vars: usize, num_chunks: usize) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    (0..len).map(F::from).collect()
}

/// A list of MLEs that represents an identity permutation
pub fn identity_permutation_mles<F: PrimeField>(
    num_vars: usize,
    num_chunks: usize,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let mut res = vec![];
    for i in 0..num_chunks {
        let shift = (i * (1usize << num_vars)) as u64;
        let s_id_vec = (shift..shift + (1u64 << num_vars)).map(F::from).collect();
        res.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars, s_id_vec,
        )));
    }
    res
}

pub fn random_permutation<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    let mut s_id_vec: Vec<F> = (0..len).map(F::from).collect();
    let mut s_perm_vec = vec![];
    for _ in 0..len {
        let index = rng.next_u64() as usize % s_id_vec.len();
        s_perm_vec.push(s_id_vec.remove(index));
    }
    s_perm_vec
}

/// A list of MLEs that represent a random permutation
pub fn random_permutation_mles<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let s_perm_vec = random_permutation(num_vars, num_chunks, rng);
    let mut res = vec![];
    let n = 1usize << num_vars;
    for i in 0..num_chunks {
        res.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            s_perm_vec[i * n..i * n + n].to_vec(),
        )));
    }
    res
}

pub fn evaluate_opt<F: Field>(poly: &DenseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(poly.num_vars, point.len());
    fix_first_variables(poly, point).evaluations[0]
}

pub fn fix_first_variables<F: Field>(
    poly: &DenseMultilinearExtension<F>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    debug_assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );
    let nv = poly.num_vars;
    let mut poly = poly.evaluations.to_vec();
    let dim = partial_point.len();
    // evaluate single variable of partial point from left to right
    for (i, point) in partial_point.iter().enumerate().take(dim) {
        poly = fix_one_variable_helper(&poly, nv - i, point);
    }

    DenseMultilinearExtension::<F>::from_evaluations_slice(
        nv - dim,
        &poly[..(1usize << (nv - dim))],
    )
}

fn fix_one_variable_helper<F: Field>(data: &[F], nv: usize, point: &F) -> Vec<F> {
    let mut res = vec![F::zero(); 1usize << (nv - 1)];

    // evaluate single variable of partial point from left to right
    #[cfg(not(feature = "parallel"))]
    for i in 0..(1usize << (nv - 1)) {
        res[i] = data[i] + (data[(i << 1) + 1] - data[i << 1]) * point;
    }

    #[cfg(feature = "parallel")]
    res.par_iter_mut().enumerate().for_each(|(i, x)| {
        *x = data[i << 1] + (data[(i << 1) + 1] - data[i << 1]) * point;
    });

    res
}

pub fn fix_last_variables<F: PrimeField>(
    poly: &DenseMultilinearExtension<F>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    debug_assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );

    let is_boolean_point = partial_point.iter().all(|&x| x.is_zero() || x.is_one());
    let nu = partial_point.len();
    let mu = poly.num_vars - nu;

    if is_boolean_point {
        // --- OPTIMIZED PATH for boolean points ---
        // This corresponds to selecting a slice from the evaluations vector.

        // Convert the boolean point to its integer representation.
        // We assume the point's variables are ordered from LSB to MSB
        // corresponding to the last `nu` variables.
        let mut target_x_index = 0;
        for (i, &bit) in partial_point.iter().enumerate() {
            if bit.is_one() {
                target_x_index |= 1usize << i;
            }
        }

        // The new polynomial's evaluations are a slice of the original.
        // The size of the slice is the number of evaluations for a mu-variate
        // polynomial.
        let slice_size = 1usize << mu;

        // The starting point of the slice is determined by the integer value
        // of the boolean point.
        let start = target_x_index * slice_size;
        let end = start + slice_size;

        let new_evals = &poly.evaluations[start..end];

        DenseMultilinearExtension::<F>::from_evaluations_slice(mu, new_evals)
    } else {
        // --- GENERAL PATH for non-boolean (random) points ---
        // This is the original, more expensive implementation.

        let mut current_evals = poly.evaluations.to_vec();

        // Evaluate single variable of partial point from right to left (MSB to LSB).
        for (i, point) in partial_point.iter().rev().enumerate() {
            current_evals = fix_last_variable_helper(&current_evals, poly.num_vars - i, point);
        }

        DenseMultilinearExtension::<F>::from_evaluations_slice(mu, &current_evals[..1usize << mu])
    }
}

fn fix_last_variable_helper<F: Field>(data: &[F], nv: usize, point: &F) -> Vec<F> {
    let half_len = 1usize << (nv - 1);
    let mut res = vec![F::zero(); half_len];

    // evaluate single variable of partial point from left to right
    #[cfg(not(feature = "parallel"))]
    for b in 0..half_len {
        res[b] = data[b] + (data[b + half_len] - data[b]) * point;
    }

    #[cfg(feature = "parallel")]
    res.par_iter_mut().enumerate().for_each(|(i, x)| {
        *x = data[i] + (data[i + half_len] - data[i]) * point;
    });

    res
}

pub fn evaluate_last_dense<F: PrimeField>(f: &DenseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(f.num_vars, point.len());
    fix_last_variables(f, point).evaluations[0]
}

pub fn fix_last_variables_sparse<F: Field + Sync>(
    poly: &SparseMultilinearExtension<F>,
    // point for the last `nu` variables (LSB-first within that last block)
    partial_point_x: &[F],
) -> SparseMultilinearExtension<F> {
    let nu = partial_point_x.len();
    debug_assert!(nu <= poly.num_vars, "invalid size of partial point");
    if nu == 0 {
        return poly.clone();
    }
    let mu = poly.num_vars - nu;

    // --- Boolean fast path: select one contiguous block of size 2^mu. ---
    if partial_point_x.iter().all(|b| b.is_zero() || b.is_one()) {
        // LSB-first inside the last block (matches your dense code):
        let mut target_x_index: usize = 0;
        for (i, bit) in partial_point_x.iter().enumerate() {
            if bit.is_one() {
                target_x_index |= 1usize << i;
            }
        }

        let slice_size = 1usize << mu;
        let start = target_x_index << mu; // == target_x_index * slice_size
        let end = start + slice_size;

        let mut out = BTreeMap::new();
        for (&full_idx, &val) in poly.evaluations.range(start..end) {
            // rebase to local y-index in [0 .. 2^mu)
            out.insert(full_idx - start, val);
        }

        // Convert to the format expected by from_evaluations
        // Need a container whose iterator yields &(usize, F), not (&usize, &F).
        let evaluations: Vec<(usize, F)> = out.into_iter().collect();
        return SparseMultilinearExtension::from_evaluations(mu, &evaluations);
    }

    // --- General path: accumulate using eq(partial_point_x) on the high bits. ---
    // Precompute equality polynomial table eq_x of length 2^nu (LSB-first).
    let eq_x = {
        let dim = partial_point_x.len();
        let mut dp = vec![F::zero(); 1 << dim];
        dp[0] = F::one() - partial_point_x[0];
        dp[1] = partial_point_x[0];
        for i in 1..dim {
            for b in 0..(1 << i) {
                let prev = dp[b];
                dp[b + (1 << i)] = prev * partial_point_x[i];
                dp[b] = prev - dp[b + (1 << i)];
            }
        }
        dp
    };

    let mut out = BTreeMap::<usize, F>::new();
    let y_mask: usize = if mu == 0 { 0 } else { (1usize << mu) - 1 };

    for (&full_idx, &val) in &poly.evaluations {
        // Split global index into high (x) and low (y) parts:
        let y_index = full_idx & y_mask; // local index in [0 .. 2^mu)
        let x_index = full_idx >> mu; // index into last-block bits [0 .. 2^nu)

        let w = eq_x[x_index];
        if !w.is_zero() {
            let entry = out.entry(y_index).or_insert(F::zero());
            *entry += w * val;
        }
    }

    let evaluations: Vec<(usize, F)> = out.into_iter().filter(|(_, v)| !v.is_zero()).collect();
    SparseMultilinearExtension::from_evaluations(mu, &evaluations)
}
pub fn evaluate_last_sparse<F: PrimeField>(f: &SparseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(f.num_vars, point.len());
    fix_last_variables_sparse(f, point).evaluations[&0]
}
pub fn partially_eval_dense_poly_on_bool_point<F: Field>(
    dense_poly: &DenseMultilinearExtension<F>,
    index: usize,
    n: usize,
) -> Vec<F> {
    cfg_iter!(dense_poly.evaluations[n * index..n * index + n])
        .cloned()
        .collect()
}

use std::ops::{Bound::Included, Bound::Excluded};

#[inline]
pub fn partially_eval_sparse_poly_on_bool_point<'a, F: 'a + Field>(
    sparse_poly: &'a SparseMultilinearExtension<F>,
    index: usize,
    n: usize,
) -> impl Iterator<Item = (usize, &'a F)> {
    debug_assert!(n > 0 && n.is_power_of_two(), "n must be a power of two");
    let total = 1usize << sparse_poly.num_vars;
    debug_assert!(n <= total, "n must be <= 2^num_vars");
    debug_assert!(total % n == 0, "n must divide 2^num_vars");
    let num_prefix_assignments = total / n;
    debug_assert!(index < num_prefix_assignments, "index out of range");

    let base = index * n;
    let mask = n - 1; // valid because n is power of two

    sparse_poly
        .evaluations
        .range((Included(base), Excluded(base + n)))
        .map(move |(&global_idx, v)| ((global_idx & mask), v))
}

pub fn fix_last_variables_boolean<F: Field>(
    poly: &DenseMultilinearExtension<F>,
    point: &[F],
) -> DenseMultilinearExtension<F> {
    let n = poly.num_vars() - point.len();
    let index = bits_le_to_usize(point);
    DenseMultilinearExtension::from_evaluations_vec(
        n,
        partially_eval_dense_poly_on_bool_point(poly, index, 1 << n),
    )
}
pub fn fix_last_variables_boolean_sparse<F: Field>(
    poly: &SparseMultilinearExtension<F>,
    point: &[F],
) -> SparseMultilinearExtension<F> {
    // remaining vars after fixing the last |point| variables
    let n = poly.num_vars() - point.len();
    // little-endian: point[0] is LSB of the last block
    let index = bits_le_to_usize(point);
    // grab the contiguous window and rebase indices to [0 .. 2^n)
    let evals_map = partially_eval_sparse_poly_on_bool_point(poly, index, 1 << n);
    let evals: Vec<(usize, F)> = evals_map.map(|(i, v)| (i, *v)).collect();

    SparseMultilinearExtension::from_evaluations(n, &evals)
}

fn rand_sparse_eval_map<F: Field, R: Rng>(
    num_vars: usize,
    sparsity: usize,
    rng: &mut R,
) -> BTreeMap<usize, F> {
    let domain_size = 1usize << num_vars;
    debug_assert!(sparsity <= domain_size, "sparsity must be <= 2^num_vars");

    // Pick `s` distinct indices uniformly (rejection sampling with a bitmask).
    let mut idxs = HashSet::with_capacity(sparsity);
    let mask = domain_size - 1; // valid because domain_size is a power of two
    while idxs.len() < sparsity {
        let i = usize::rand(rng) & mask;
        idxs.insert(i);
    }

    // Assign random non-zero field values to those indices, collect into a
    // BTreeMap.
    let mut map = BTreeMap::new();
    for i in idxs {
        let mut v = F::rand(rng);
        while v.is_zero() {
            v = F::rand(rng);
        }
        map.insert(i, v);
    }
    map
}

pub fn rand_sparse_mle<F: Field, R: Rng>(
    num_vars: usize,
    sparsity: usize,
    rng: &mut R,
) -> SparseMultilinearExtension<F> {
    let map = rand_sparse_eval_map::<F, _>(num_vars, sparsity, rng);
    // Convert map -> Vec<(usize, F)> to use your existing constructor
    let pairs: Vec<(usize, F)> = map.iter().map(|(&i, &v)| (i, v)).collect();
    SparseMultilinearExtension::from_evaluations(num_vars, &pairs)
}

#[cfg(test)]
mod fix_last_sparse_vs_dense {
    use std::collections::HashSet;

    use super::*; // brings types + functions from the current module (adjust if needed)
    use ark_bn254::Fr;
    use ark_ff::Field;
    use ark_poly::MultilinearExtension;
    use ark_std::{rand::Rng, test_rng, One, UniformRand, Zero};
    /// Helper: build a truly sparse MLE from a dense one by dropping zeros.
    fn dense_to_sparse<F: Field>(
        dense: &DenseMultilinearExtension<F>,
    ) -> SparseMultilinearExtension<F> {
        let pairs: Vec<(usize, F)> = dense
            .evaluations
            .iter()
            .enumerate()
            .filter_map(|(i, v)| if v.is_zero() { None } else { Some((i, *v)) })
            .collect();
        SparseMultilinearExtension::from_evaluations(dense.num_vars, &pairs)
    }

    /// Compare dense fix_last vs sparse fix_last on the *same* polynomial.
    #[test]
    fn fix_last_sparse_matches_dense_boolean_and_random() {
        let mut rng = test_rng();
        const NV: usize = 8; // keep small for fast tests

        for _trial in 0..40 {
            // random dense poly
            let evals: Vec<Fr> = (0..(1usize << NV)).map(|_| Fr::rand(&mut rng)).collect();
            let dense = DenseMultilinearExtension::from_evaluations_vec(NV, evals.clone());
            let sparse = dense_to_sparse(&dense);

            for nu in 0..=NV {
                // ---- boolean point (fast path) ----
                let bpoint: Vec<Fr> = (0..nu)
                    .map(|_| {
                        if bool::rand(&mut rng) {
                            Fr::one()
                        } else {
                            Fr::zero()
                        }
                    })
                    .collect();

                let d_fix = fix_last_variables(&dense, &bpoint);
                let s_fix = fix_last_variables_sparse(&sparse, &bpoint);

                assert_eq!(
                    d_fix.to_evaluations(),
                    s_fix.to_dense_multilinear_extension().evaluations,
                    "boolean mismatch at nu={}",
                    nu
                );

                // ---- random (non-boolean) point (general path) ----
                let rpoint: Vec<Fr> = (0..nu).map(|_| Fr::rand(&mut rng)).collect();

                let d_fix = fix_last_variables(&dense, &rpoint);
                let s_fix = fix_last_variables_sparse(&sparse, &rpoint);

                assert_eq!(
                    d_fix.to_evaluations(),
                    s_fix.to_dense_multilinear_extension().evaluations,
                    "random mismatch at nu={}",
                    nu
                );
            }
        }
    }

    /// Extra sanity: extreme sparsity + edge cases nu=0 and nu=NV.
    #[test]
    fn fix_last_sparse_edge_cases_and_extreme_sparsity() {
        let mut rng = test_rng();
        const NV: usize = 10;

        // Extremely sparse: only K non-zeros at random indices.
        let k_nonzeros = 7usize;
        let mut indices = std::collections::BTreeSet::new();
        while indices.len() < k_nonzeros {
            indices.insert(usize::rand(&mut rng) & ((1usize << NV) - 1));
        }
        let pairs: Vec<(usize, Fr)> = indices
            .into_iter()
            .map(|i| (i, Fr::rand(&mut rng)))
            .collect();

        let sparse = SparseMultilinearExtension::from_evaluations(NV, &pairs);
        let dense = sparse.to_dense_multilinear_extension();

        // nu = 0 (no fixing): identity
        {
            let d_fix = fix_last_variables(&dense, &[]);
            let s_fix = fix_last_variables_sparse(&sparse, &[]);
            assert_eq!(
                d_fix.to_evaluations(),
                s_fix.to_dense_multilinear_extension().evaluations
            );
            assert_eq!(d_fix.to_evaluations(), dense.evaluations);
        }

        // nu = NV (fully fixed): constant
        {
            // boolean point
            let bpoint: Vec<Fr> = (0..NV)
                .map(|_| {
                    if bool::rand(&mut rng) {
                        Fr::one()
                    } else {
                        Fr::zero()
                    }
                })
                .collect();
            let d_fix = fix_last_variables(&dense, &bpoint);
            let s_fix = fix_last_variables_sparse(&sparse, &bpoint);
            assert_eq!(
                d_fix.to_evaluations(),
                s_fix.to_dense_multilinear_extension().evaluations
            );

            // random point
            let rpoint: Vec<Fr> = (0..NV).map(|_| Fr::rand(&mut rng)).collect();
            let d_fix = fix_last_variables(&dense, &rpoint);
            let s_fix = fix_last_variables_sparse(&sparse, &rpoint);
            assert_eq!(
                d_fix.to_evaluations(),
                s_fix.to_dense_multilinear_extension().evaluations
            );
        }
    }
}
