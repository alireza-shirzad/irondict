use ark_ec::{pairing::Pairing, CurveGroup};

use crate::poly::DenseOrSparseMLE;
use ark_serialize::{
    self, CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid,
    Validate, Write,
};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, ops::Sub, Zero};
use derivative::Derivative;
use ndarray::{ArrayD, IxDyn};
#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
use std::ops::{Add, Deref, DerefMut};
///////////////// Commitment //////////////////////

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
/// A commitment is an Affine point.
pub struct KZHKCommitment<E: Pairing> {
    /// the actual commitment is an affine point.
    com: E::G1Affine,
    nv: usize,
}
impl<E: Pairing> Add for KZHKCommitment<E> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        debug_assert_eq!(self.nv, other.nv, "commitments for different nv!");
        let com = (self.com + other.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<E: Pairing> Sub for KZHKCommitment<E> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        debug_assert_eq!(self.nv, other.nv, "commitments for different nv!");
        let com = (self.com - other.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<'b, E: Pairing> Add<&'b KZHKCommitment<E>> for &KZHKCommitment<E> {
    type Output = KZHKCommitment<E>;

    fn add(self, rhs: &'b KZHKCommitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com + rhs.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<'b, E: Pairing> Sub<&'b KZHKCommitment<E>> for &KZHKCommitment<E> {
    type Output = KZHKCommitment<E>;

    fn sub(self, rhs: &'b KZHKCommitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com - rhs.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<E: Pairing> KZHKCommitment<E> {
    /// Create a new commitment
    pub fn new(com: E::G1Affine, nv: usize) -> Self {
        Self { com, nv }
    }

    /// Get the commitment
    pub fn get_commitment(&self) -> E::G1Affine {
        self.com
    }

    /// Get the number of variables
    pub fn get_num_vars(&self) -> usize {
        self.nv
    }
}

////////////// Auxiliary information /////////////////

#[derive(Debug, Derivative, CanonicalSerialize, CanonicalDeserialize, Clone, PartialEq, Eq)]
pub struct KZHKAuxInfo<E: Pairing> {
    tau: Option<E::ScalarField>,
    d_bool: Option<Vec<Vec<E::G1Affine>>>,
}

impl<E: Pairing> KZHKAuxInfo<E> {
    /// Create a new auxiliary information
    pub fn new(tau: Option<E::ScalarField>, d_bool: Option<Vec<Vec<E::G1Affine>>>) -> Self {
        Self { tau, d_bool }
    }

    /// Get the auxiliary information
    pub fn get_d_bool(&self) -> &Vec<Vec<E::G1Affine>> {
        self.d_bool.as_ref().unwrap()
    }

    /// Get the auxiliary information
    pub fn get_tau(&self) -> &E::ScalarField {
        self.tau.as_ref().unwrap()
    }

    pub fn set_d_bool(&mut self, d_bool: Vec<Vec<E::G1Affine>>) {
        self.d_bool = Some(d_bool);
    }
}

impl<E: Pairing> Default for KZHKAuxInfo<E> {
    fn default() -> Self {
        KZHKAuxInfo {
            d_bool: None,
            tau: None,
        }
    }
}

impl<E: Pairing> Add for KZHKAuxInfo<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self == KZHKAuxInfo::default() {
            return rhs;
        }
        if rhs == KZHKAuxInfo::default() {
            return self;
        }
        assert_eq!(
            self.d_bool.as_ref().unwrap().len(),
            rhs.d_bool.as_ref().unwrap().len(),
            "Auxiliary information must have the same length"
        );
        let out_d_bool = cfg_iter!(self.d_bool.as_ref().unwrap())
            .zip(cfg_iter!(rhs.d_bool.as_ref().unwrap()))
            .map(|(ra, rb)| {
                assert_eq!(ra.len(), rb.len(), "column count mismatch in a row");
                cfg_iter!(ra)
                    .cloned()
                    .zip(cfg_iter!(rb))
                    .map(|(x, y)| (x + y).into_affine())
                    .collect()
            })
            .collect();
        KZHKAuxInfo {
            d_bool: Some(out_d_bool),
            tau: None,
        }
    }
}

impl<E: Pairing> Sub for KZHKAuxInfo<E> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self == KZHKAuxInfo::default() {
            return rhs;
        }
        if rhs == KZHKAuxInfo::default() {
            return self;
        }
        assert_eq!(
            self.d_bool.as_ref().unwrap().len(),
            rhs.d_bool.as_ref().unwrap().len(),
            "Auxiliary information must have the same length"
        );
        let out_d_bool = cfg_iter!(self.d_bool.as_ref().unwrap())
            .zip(cfg_iter!(rhs.d_bool.as_ref().unwrap()))
            .map(|(ra, rb)| {
                assert_eq!(ra.len(), rb.len(), "column count mismatch in a row");
                cfg_iter!(ra)
                    .cloned()
                    .zip(cfg_iter!(rb))
                    .map(|(x, y)| (x - y).into_affine())
                    .collect()
            })
            .collect();
        KZHKAuxInfo {
            d_bool: Some(out_d_bool),
            tau: None,
        }
    }
}

///////////// Opening Proof /////////////////

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]

/// proof of opening
pub struct KZHKOpeningProof<E: Pairing> {
    d: Vec<Vec<E::G1Affine>>,
    f: DenseOrSparseMLE<E::ScalarField>,
    r_hide: Option<KZHKCommitment<E>>,
    y_r: Option<E::ScalarField>,
    rho_prime: Option<E::ScalarField>,
}

impl<E: Pairing> KZHKOpeningProof<E> {
    /// Create a new opening proof
    pub fn new(
        d: Vec<Vec<E::G1Affine>>,
        f: DenseOrSparseMLE<E::ScalarField>,
        r_hide: Option<KZHKCommitment<E>>,
        y_r: Option<E::ScalarField>,
        rho_prime: Option<E::ScalarField>,
    ) -> Self {
        Self {
            d,
            f,
            r_hide,
            y_r,
            rho_prime,
        }
    }

    /// Get the evaluation of quotients
    pub fn get_d(&self) -> &Vec<Vec<E::G1Affine>> {
        &self.d
    }

    /// Get the opening proof
    pub fn get_f(&self) -> &DenseOrSparseMLE<E::ScalarField> {
        &self.f
    }

    pub fn get_r_hide(&self) -> &Option<KZHKCommitment<E>> {
        &self.r_hide
    }

    /// Get the y_r value
    pub fn get_y_r(&self) -> &Option<E::ScalarField> {
        &self.y_r
    }

    /// Get the rho_prime value
    pub fn get_rho_prime(&self) -> &Option<E::ScalarField> {
        &self.rho_prime
    }

    pub fn set_rho_prime(&mut self, rho_prime: E::ScalarField) {
        self.rho_prime = Some(rho_prime);
    }

    pub fn set_y_r(&mut self, y_r: E::ScalarField) {
        self.y_r = Some(y_r);
    }

    pub fn set_r_hide(&mut self, r_hide: KZHKCommitment<E>) {
        self.r_hide = Some(r_hide);
    }
}

impl<E: Pairing> Default for KZHKOpeningProof<E> {
    fn default() -> Self {
        KZHKOpeningProof {
            d: vec![],
            f: DenseOrSparseMLE::zero(),
            r_hide: None,
            y_r: None,
            rho_prime: None,
        }
    }
}

impl<E: Pairing> core::ops::Mul<E::ScalarField> for KZHKOpeningProof<E> {
    type Output = Self;

    fn mul(self, rhs: E::ScalarField) -> Self::Output {
        if rhs.is_zero() {
            return Self::default();
        }
        if self == Self::default() {
            return self;
        }
        let out_d = cfg_into_iter!(self.d)
            .map(|row| {
                cfg_into_iter!(row)
                    .map(|x| (x * rhs).into_affine())
                    .collect()
            })
            .collect();
        let mut f_out = self.f;
        mul_poly_by_cnst_in_place(&mut f_out, rhs);
        KZHKOpeningProof {
            d: out_d,
            f: f_out,
            r_hide: None,
            y_r: None,
            rho_prime: None,
        }
    }
}

impl<'a, E: Pairing> core::ops::Mul<E::ScalarField> for &'a KZHKOpeningProof<E> {
    type Output = KZHKOpeningProof<E>;

    fn mul(self, rhs: E::ScalarField) -> Self::Output {
        if rhs.is_zero() {
            return KZHKOpeningProof::default();
        }
        let out_d = self
            .d
            .iter()
            .map(|row| {
                row.iter()
                    .cloned()
                    .map(|x| (x * rhs).into_affine())
                    .collect()
            })
            .collect();
        let mut f_out = self.f.clone();
        mul_poly_by_cnst_in_place(&mut f_out, rhs);
        KZHKOpeningProof {
            d: out_d,
            f: f_out,
            r_hide: None,
            y_r: None,
            rho_prime: None,
        }
    }
}

impl<E: Pairing> core::ops::MulAssign<E::ScalarField> for KZHKOpeningProof<E> {
    fn mul_assign(&mut self, rhs: E::ScalarField) {
        if rhs.is_zero() {
            self.d.clear();
            self.f = DenseOrSparseMLE::zero();
            return;
        }
        for row in self.d.iter_mut() {
            for x in row.iter_mut() {
                *x = (*x * rhs).into_affine();
            }
        }
        mul_poly_by_cnst_in_place(&mut self.f, rhs);
    }
}

impl<E: Pairing> Add for KZHKOpeningProof<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self == KZHKOpeningProof::default() {
            return rhs;
        }
        if rhs == KZHKOpeningProof::default() {
            return self;
        }
        assert_eq!(
            self.d.len(),
            rhs.d.len(),
            "Auxiliary information must have the same length"
        );
        let out_d = self
            .d
            .iter()
            .zip(rhs.d.iter())
            .map(|(ra, rb)| {
                assert_eq!(ra.len(), rb.len(), "column count mismatch in a row");
                ra.iter()
                    .cloned()
                    .zip(rb.iter().cloned())
                    .map(|(x, y)| (x + y).into_affine())
                    .collect()
            })
            .collect();

        let f_out = match (&self.f, &rhs.f) {
            (DenseOrSparseMLE::Dense(ref a), DenseOrSparseMLE::Dense(ref b)) => {
                DenseOrSparseMLE::Dense(a + b)
            },
            (DenseOrSparseMLE::Sparse(ref a), DenseOrSparseMLE::Sparse(ref b)) => {
                DenseOrSparseMLE::Sparse(a + b)
            },
            (DenseOrSparseMLE::Dense(ref a), DenseOrSparseMLE::Sparse(ref _b)) => {
                let densed_b = rhs.f.to_dense();
                DenseOrSparseMLE::Dense(a + &densed_b)
            },
            (DenseOrSparseMLE::Sparse(ref _a), DenseOrSparseMLE::Dense(ref b)) => {
                let densed_a = self.f.to_dense();
                DenseOrSparseMLE::Dense(&densed_a + b)
            },
        };

        KZHKOpeningProof {
            d: out_d,
            f: f_out,
            r_hide: None,
            y_r: None,
            rho_prime: None,
        }
    }
}

impl<E: Pairing> Sub for KZHKOpeningProof<E> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        if self == KZHKOpeningProof::default() {
            return rhs;
        }
        if rhs == KZHKOpeningProof::default() {
            return self;
        }
        assert_eq!(
            self.d.len(),
            rhs.d.len(),
            "Auxiliary information must have the same length"
        );
        let out_d = self
            .d
            .iter()
            .zip(rhs.d.iter())
            .map(|(ra, rb)| {
                assert_eq!(ra.len(), rb.len(), "column count mismatch in a row");
                ra.iter()
                    .cloned()
                    .zip(rb.iter().cloned())
                    .map(|(x, y)| (x - y).into_affine())
                    .collect()
            })
            .collect();
        let f_out = self.f - rhs.f;
        KZHKOpeningProof {
            d: out_d,
            f: f_out,
            r_hide: None,
            y_r: None,
            rho_prime: None,
        }
    }
}
///////////////// Tensor and implementation ///////////////////

/// Local newtype wrapper around `ndarray::ArrayD<T>` so we can implement
/// `CanonicalSerialize`/`CanonicalDeserialize` without violating the orphan
/// rules.
#[derive(Clone, Debug)]
pub struct Tensor<T>(pub ArrayD<T>);

impl<T> From<ArrayD<T>> for Tensor<T> {
    fn from(a: ArrayD<T>) -> Self {
        Tensor(a)
    }
}
impl<T> From<Tensor<T>> for ArrayD<T> {
    fn from(w: Tensor<T>) -> Self {
        w.0
    }
}
impl<T> Deref for Tensor<T> {
    type Target = ArrayD<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> DerefMut for Tensor<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn product_u64(shape: &[usize]) -> Result<u64, SerializationError> {
    let mut acc: u128 = 1;
    for &d in shape {
        acc = acc
            .checked_mul(d as u128)
            .ok_or(SerializationError::InvalidData)?;
    }
    u64::try_from(acc).map_err(|_| SerializationError::InvalidData)
}

/// Iterator to walk all indices in row-major order for a given shape.
struct RowMajorIx {
    idx: Vec<usize>,
    shape: Vec<usize>,
    done: bool,
}
impl RowMajorIx {
    fn new(shape: &[usize]) -> Self {
        let k = shape.len();
        let done = shape.contains(&0);
        Self {
            idx: vec![0; k],
            shape: shape.to_vec(),
            done,
        }
    }
}
impl Iterator for RowMajorIx {
    type Item = IxDyn;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let out = IxDyn(&self.idx);
        for ax in (0..self.shape.len()).rev() {
            self.idx[ax] += 1;
            if self.idx[ax] < self.shape[ax] {
                break;
            } else {
                self.idx[ax] = 0;
                if ax == 0 {
                    self.done = true;
                }
            }
        }
        Some(out)
    }
}

impl<T: CanonicalSerialize> CanonicalSerialize for Tensor<T> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut w: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // rank
        let rank = u32::try_from(self.ndim()).map_err(|_| SerializationError::InvalidData)?;
        rank.serialize_with_mode(&mut w, compress)?;
        // shape
        for &d in self.shape() {
            let d64 = u64::try_from(d).map_err(|_| SerializationError::InvalidData)?;
            d64.serialize_with_mode(&mut w, compress)?;
        }
        // element count
        let n = product_u64(self.shape())?;
        n.serialize_with_mode(&mut w, compress)?;
        // elements in row-major order
        let shape = self.shape().to_vec();
        if self.is_standard_layout() {
            if let Some(slice) = self.as_slice_memory_order() {
                for t in slice {
                    t.serialize_with_mode(&mut w, compress)?;
                }
                return Ok(());
            }
        }
        for ix in RowMajorIx::new(&shape) {
            self[ix].serialize_with_mode(&mut w, compress)?;
        }
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut sz = 0usize;
        sz += u32::default().serialized_size(compress);
        sz += self.shape().len() * u64::default().serialized_size(compress);
        sz += u64::default().serialized_size(compress);
        if self.is_standard_layout() {
            if let Some(slice) = self.as_slice_memory_order() {
                return sz
                    + slice
                        .iter()
                        .map(|t| t.serialized_size(compress))
                        .sum::<usize>();
            }
        }
        let shape = self.shape().to_vec();
        sz + RowMajorIx::new(&shape)
            .map(|ix| self[ix].serialized_size(compress))
            .sum::<usize>()
    }
}

impl<T: Valid> Valid for Tensor<T> {
    fn check(&self) -> Result<(), SerializationError> {
        // Check each element
        if self.is_standard_layout() {
            if let Some(slice) = self.as_slice_memory_order() {
                for t in slice {
                    t.check()?;
                }
                return Ok(());
            }
        }

        let shape = self.shape().to_vec();
        for ix in RowMajorIx::new(&shape) {
            self[ix].check()?;
        }
        Ok(())
    }
}

impl<T: Valid + CanonicalDeserialize> CanonicalDeserialize for Tensor<T> {
    fn deserialize_with_mode<R: Read>(
        mut r: R,
        compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let k = u32::deserialize_with_mode(&mut r, compress, Validate::No)?;
        let k = usize::try_from(k).map_err(|_| SerializationError::InvalidData)?;
        // shape
        let mut shape = Vec::with_capacity(k);
        for _ in 0..k {
            let d = u64::deserialize_with_mode(&mut r, compress, Validate::No)?;
            shape.push(usize::try_from(d).map_err(|_| SerializationError::InvalidData)?);
        }
        // element count check
        let n_hdr = u64::deserialize_with_mode(&mut r, compress, Validate::No)?;
        let n_calc = product_u64(&shape)?;
        if n_hdr != n_calc {
            return Err(SerializationError::InvalidData);
        }
        let n = usize::try_from(n_calc).map_err(|_| SerializationError::InvalidData)?;
        // elements in row-major order
        let mut data = Vec::with_capacity(n);
        for _ in 0..n {
            data.push(T::deserialize_with_mode(&mut r, compress, Validate::No)?);
        }
        let arr = ArrayD::from_shape_vec(IxDyn(&shape), data)
            .map_err(|_| SerializationError::InvalidData)?;
        Ok(Tensor(arr))
    }
}

fn mul_poly_by_cnst_in_place<F>(poly: &mut DenseOrSparseMLE<F>, c: F)
where
    F: ark_ff::Field,
{
    match poly {
        DenseOrSparseMLE::Dense(dense) => {
            cfg_iter_mut!(dense.evaluations).for_each(|x| {
                *x *= c;
            });
        },
        DenseOrSparseMLE::Sparse(sparse) => {
            cfg_iter_mut!(sparse.evaluations).for_each(|(_, x)| {
                *x *= c;
            });
        },
    }
}
