use ark_ec::pairing::Pairing;
use ark_std::log2;

use crate::{VKDKey, VKDPublicParameters, VKDSpecification, structs::IronSpecification};
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use subroutines::{PolynomialCommitmentScheme, poly::DenseOrSparseMLE};

pub struct IronPublicParameters<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    specification: IronSpecification,
    pcs_ck: MvPCS::ProverParam,
    pcs_vk: MvPCS::VerifierParam,
}

impl<E, MvPCS> VKDKey for IronPublicParameters<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    fn get_specification(&self) -> &dyn VKDSpecification {
        &self.specification
    }
}

impl<E, MvPCS> VKDPublicParameters for IronPublicParameters<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    type ServerKey = IronServerKey<E, MvPCS>;
    type AuditorKey = IronAuditorKey<E, MvPCS>;
    type ClientKey = IronClientKey<E, MvPCS>;

    fn to_server_key(&self) -> Self::ServerKey {
        IronServerKey::new(self.specification.clone(), self.pcs_ck.clone())
    }

    fn to_auditor_key(&self) -> Self::AuditorKey {
        IronAuditorKey::new(self.specification.clone(), self.pcs_vk.clone())
    }

    fn to_client_key(&self) -> Self::ClientKey {
        IronClientKey::new(self.specification.clone(), self.pcs_vk.clone())
    }
}

impl<E, MvPCS> IronPublicParameters<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(specification: IronSpecification, pcs_param: MvPCS::SRS) -> Self {
        let (pcs_ck, pcs_vk) = MvPCS::trim(
            pcs_param,
            None,
            Some(specification.get_capacity().trailing_zeros() as usize),
        )
        .unwrap();
        Self {
            specification,
            pcs_ck,
            pcs_vk,
        }
    }
}

pub struct IronServerKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    specification: IronSpecification,
    pcs_prover_param: MvPCS::ProverParam,
}

impl<E, MvPCS> IronServerKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(specification: IronSpecification, pcs_prover_param: MvPCS::ProverParam) -> Self {
        Self {
            specification,
            pcs_prover_param,
        }
    }

    pub fn get_pcs_prover_param(&self) -> &MvPCS::ProverParam {
        &self.pcs_prover_param
    }
}

impl<E, MvPCS> VKDKey for IronServerKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    fn get_specification(&self) -> &dyn VKDSpecification {
        &self.specification
    }
}

pub struct IronAuditorKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    specification: IronSpecification,
    pcs_verifier_param: MvPCS::VerifierParam,
}

impl<E, MvPCS> IronAuditorKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(specification: IronSpecification, pcs_verifier_param: MvPCS::VerifierParam) -> Self {
        Self {
            specification,
            pcs_verifier_param,
        }
    }
    pub fn get_pcs_verifier_param(&self) -> &MvPCS::VerifierParam {
        &self.pcs_verifier_param
    }
}

impl<E, MvPCS> VKDKey for IronAuditorKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    fn get_specification(&self) -> &dyn VKDSpecification {
        &self.specification
    }
}

#[derive(Clone, CanonicalSerialize)]
pub struct IronClientKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    specification: IronSpecification,
    pcs_verifier_param: MvPCS::VerifierParam,
}

impl<E, MvPCS> IronClientKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(specification: IronSpecification, pcs_verifier_param: MvPCS::VerifierParam) -> Self {
        Self {
            specification,
            pcs_verifier_param,
        }
    }

    pub fn get_pcs_verifier_param(&self) -> &MvPCS::VerifierParam {
        &self.pcs_verifier_param
    }
}

impl<E, MvPCS> VKDKey for IronClientKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    fn get_specification(&self) -> &dyn VKDSpecification {
        &self.specification
    }
}
