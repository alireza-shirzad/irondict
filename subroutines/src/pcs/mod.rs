mod errors;
pub mod kzhk;
pub mod prelude;
mod structs;

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use errors::PCSError;
use std::{borrow::Borrow, default, fmt::Debug, hash::Hash};
use transcript::IOPTranscript;

/// This trait defines APIs for polynomial commitment schemes.
pub trait PolynomialCommitmentScheme<E: Pairing> {
    type Config: Clone + Debug + Default;
    type ProverParam: Clone + Sync;
    type VerifierParam: Clone + CanonicalSerialize + CanonicalDeserialize;
    type SRS: Clone + Debug + CanonicalSerialize + CanonicalDeserialize;
    type Polynomial: Clone + Debug + Hash + PartialEq + Eq;
    type Point: Clone + Ord + Debug + Sync + Hash + PartialEq + Eq;
    type Evaluation: Field;
    type Commitment: Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Debug
        + PartialEq
        + Eq
        + Default
        + Send
        + Sync;
    type Proof: Clone + CanonicalSerialize + CanonicalDeserialize + Debug + PartialEq + Eq;
    type BatchProof: CanonicalSerialize + CanonicalDeserialize + Clone + Debug + Eq;
    type Aux: Clone
        + CanonicalSerialize
        + CanonicalDeserialize
        + Debug
        + PartialEq
        + Eq
        + Send
        + Default
        + Sync;

    fn gen_srs_for_testing<R: Rng>(
        conf: Option<Self::Config>,
        rng: &mut R,
        supported_size: usize,
        zk: bool,
    ) -> Result<Self::SRS, PCSError>;

    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<(Self::Commitment, Self::Aux), PCSError>;

    fn update_aux(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        com: &Self::Commitment,
        aux: &mut Self::Aux,
    ) -> Result<(), PCSError> {
        unimplemented!()
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        commitment: &Self::Commitment,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
        aux: &Self::Aux,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError>;

    fn multi_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        commitment: &Self::Commitment,
        _polynomials: &[&Self::Polynomial],
        _point: &Self::Point,
        _auxes: &[Self::Aux],
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(Self::BatchProof, Self::Evaluation), PCSError> {
        unimplemented!()
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError>;

    fn batch_verify(
        _verifier_param: &Self::VerifierParam,
        _commitments: &[Self::Commitment],
        _auxs: Option<&[Self::Aux]>,
        _point: &Self::Point,
        _values: &[E::ScalarField],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        unimplemented!()
    }
}

/// API definitions for structured reference string
pub trait StructuredReferenceString<E: Pairing>: Sized + PCSGlobalParam {
    /// Prover parameters
    type ProverParam: PCSGlobalParam;
    /// Verifier parameters
    type VerifierParam:PCSGlobalParam;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_size: usize) -> Self::ProverParam;
    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_size: usize) -> Self::VerifierParam;

    /// Trim the universal parameters to specialize the public parameters
    /// for polynomials to the given `supported_size`, and
    /// returns committer key and verifier key.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is 2 to the number of
    ///   variables.
    ///
    /// `supported_log_size` should be in range `1..=params.log_size`
    fn trim(
        &self,
        supported_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError>;

    /// Build SRS for testing.
    ///
    /// - For univariate polynomials, `supported_size` is the maximum degree.
    /// - For multilinear polynomials, `supported_size` is the number of
    ///   variables.
    ///
    /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
    /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
    fn gen_srs_for_testing<R: Rng>(
        rng: &mut R,
        k: usize,
        zk: bool,
        supported_size: usize,
    ) -> Result<Self, PCSError>;
}

pub trait PCSGlobalParam {
    fn is_zk(&self) -> bool;
}