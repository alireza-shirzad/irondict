use std::{fmt::Debug, hash::Hash};

use ark_ec::pairing::Pairing;
use errors::VKDError;
use subroutines::PolynomialCommitmentScheme;
pub mod auditor;
pub mod bb;
pub mod client;
pub mod errors;
pub mod ironkey;
pub mod server;
pub mod structs;
pub mod utils;

type VKDResult<T> = Result<T, VKDError>;

pub trait VKD<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    type Server: VKDServer<
            E,
            PC,
            Dictionary = Self::Dictionary,
            LookupProof = Self::LookupProof,
            SelfAuditProof = Self::SelfAuditProof,
        >;
    type Auditor: VKDAuditor<
            E,
            PC,
            Dictionary = Self::Dictionary,
            UpdateProof = Self::UpdateProof,
            StateCommitment = Self::StateCommitment,
        >;
    type Client: VKDClient<
            E,
            PC,
            Dictionary = Self::Dictionary,
            LookupProof = Self::LookupProof,
            SelfAuditProof = Self::SelfAuditProof,
        >;
    type Specification: VKDSpecification;
    type PublicParameters;
    type Dictionary: VKDDictionary<E, Label = Self::Label>;
    type Label: VKDLabel<E>;
    type LookupProof;
    type SelfAuditProof;
    type UpdateProof;
    type StateCommitment;
    fn setup(system_spec: Self::Specification) -> VKDResult<Self::PublicParameters>;
}

pub trait VKDServer<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    type UpdateBatch;
    type StateCommitment;
    type Dictionary: VKDDictionary<E>;
    type BulletinBoard;
    type LookupProof;
    type UpdateProof;
    type SelfAuditProof;
    type ServerKey;
    type PublicParameters: VKDPublicParameters;
    fn init(pp: &Self::PublicParameters) -> Self;
    fn update_reg(
        &mut self,
        update_batch: &Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()>;
    fn update_keys(
        &mut self,
        update_batch: &Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()>;
    fn lookup_prove(
        &self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<Self::LookupProof>;
    fn self_audit_prove(
        &self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
    ) -> VKDResult<Self::SelfAuditProof>;
}

pub trait VKDClient<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    type Dictionary: VKDDictionary<E>;
    type LookupProof;
    type SelfAuditProof;
    type ClientKey;
    type BulletinBoard;
    fn init(key: Self::ClientKey, label: <Self::Dictionary as VKDDictionary<E>>::Label) -> Self;
    fn lookup_verify(
        &mut self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
        value: <Self::Dictionary as VKDDictionary<E>>::Value,
        proof: &Self::LookupProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool>;

    fn self_audit_verify(
        &mut self,
        proof: Self::SelfAuditProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<()>;
    fn get_key(&self) -> &Self::ClientKey;
    fn get_label(&self) -> <Self::Dictionary as VKDDictionary<E>>::Label;
}

pub trait VKDAuditor<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    type Dictionary: VKDDictionary<E>;
    type UpdateProof;
    type StateCommitment;
    type BulletinBoard;
    type AuditorKey;
    fn init(key: Self::AuditorKey) -> Self;
    fn verify_update(&self, bulltin_board: &Self::BulletinBoard) -> VKDResult<bool>;
}

pub trait VKDDictionary<E: Pairing> {
    type Label: VKDLabel<E>;
    type Value;
}

pub trait VKDSpecification {
    fn get_capacity(&self) -> usize;
    fn is_zk(&self) -> bool;
}

pub trait VKDPublicParameters {
    type ServerKey: VKDKey;
    type AuditorKey: VKDKey;
    type ClientKey: VKDKey;

    fn to_server_key(&self) -> Self::ServerKey;
    fn to_auditor_key(&self) -> Self::AuditorKey;
    fn to_client_key(&self) -> Self::ClientKey;
}

pub trait VKDLabel<E: Pairing>: Debug + Hash + Eq + ToString + Clone {
    fn to_field(&self) -> E::ScalarField;
}


pub trait VKDKey {
    fn get_specification(&self) -> &dyn VKDSpecification;
}