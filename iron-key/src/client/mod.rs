pub(crate) mod errors;

use crate::VKDKey;
use ark_ec::pairing::Pairing;
use std::{
    hash,
    marker::PhantomData,
    ops::{Add, Sub},
};

use ark_poly::Polynomial;
use ark_std::{end_timer, start_timer};
use subroutines::{PolyIOP, PolynomialCommitmentScheme, SumCheck, poly::DenseOrSparseMLE};
use transcript::IOPTranscript;

use crate::{
    VKDClient, VKDDictionary, VKDLabel, VKDResult,
    bb::{BulletinBoard, dummybb::DummyBB},
    errors::VKDError,
    structs::{
        dictionary::IronDictionary, lookup::IronLookupProof, pp::IronClientKey,
        self_audit::IronSelfAuditProof,
    },
    utils::hash_to_mu_bits_with_offset,
};

pub struct IronClient<
    E: Pairing,
    T: VKDLabel<E>,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
> {
    key: IronClientKey<E, MvPCS>,
    index: Option<<MvPCS::Polynomial as Polynomial<E::ScalarField>>::Point>,
    label: T,
}

impl<E, T, MvPCS> VKDClient<E, MvPCS> for IronClient<E, T, MvPCS>
where
    E: Pairing,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
    T: VKDLabel<E>,
{
    type Dictionary = IronDictionary<E, T>;
    type ClientKey = IronClientKey<E, MvPCS>;
    type LookupProof = IronLookupProof<E, MvPCS>;

    type SelfAuditProof = IronSelfAuditProof<E, MvPCS>;
    type BulletinBoard = DummyBB<E, MvPCS>;

    fn init(key: Self::ClientKey, label: T) -> Self {
        Self {
            key,
            index: None,
            label,
        }
    }

    fn get_key(&self) -> &Self::ClientKey {
        &self.key
    }

    fn get_label(&self) -> <Self::Dictionary as VKDDictionary<E>>::Label {
        self.label.clone()
    }

    fn lookup_verify(
        &mut self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
        value: <Self::Dictionary as VKDDictionary<E>>::Value,
        proof: &Self::LookupProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool>
    where
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    {
        // TODO: Fix this for real scenarios
        let timer = start_timer!(|| "lookup_verify");
        let get_message_timer = start_timer!(|| "lookup_verify::get_last_reg_update_message");
        let last_reg_message = bulletin_board.get_last_reg_update_message().unwrap();
        let last_keys_message = bulletin_board.get_last_key_update_message().unwrap();
        end_timer!(get_message_timer);
        let mvpcs_verify_timer = start_timer!(|| "lookup_verify::mvpcs_verify");
        let mvpcs_verify_timer1 = start_timer!(|| "lookup_verify::mvpcs_verify1");
        let mut transcript = PolyIOP::<E::ScalarField>::init_transcript();
        let value_result = MvPCS::verify(
            self.key.get_pcs_verifier_param(),
            last_keys_message.get_value_commitment(),
            &proof.get_index(),
            &value,
            proof.get_value_opening_proof().0,
            &mut transcript,
        )
        .map_err(|_| VKDError::ClientError(errors::ClientError::LookupFailed))?;
        end_timer!(mvpcs_verify_timer1);
        let mvpcs_verify_timer2 = start_timer!(|| "lookup_verify::mvpcs_verify2");
        self.index = Some(proof.get_index().clone());
        let label_result = MvPCS::verify(
            self.key.get_pcs_verifier_param(),
            last_reg_message.get_label_commitment(),
            &proof.get_index(),
            &label.to_field(),
            proof.get_label_opening_proof().0,
            &mut transcript,
        )
        .map_err(|_| VKDError::ClientError(errors::ClientError::LookupFailed))?;
        end_timer!(mvpcs_verify_timer2);
        end_timer!(mvpcs_verify_timer);

        let b = value_result && label_result;
        let hash = start_timer!(|| "lookup_verify::hash");
        let (_label, _) = hash_to_mu_bits_with_offset::<E::ScalarField>(
            &self.label.to_string(),
            0,
            self.key.get_specification().get_capacity().trailing_zeros() as usize,
        );
        end_timer!(hash);
        end_timer!(timer);
        Ok(b)
    }

    fn self_audit_verify(
        &mut self,
        proof: Self::SelfAuditProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<()> {
        // let last_epoch_message = bulletin_board.read_last()?;
        // let last_accumulator = last_epoch_message.get_difference_accumulator();
        // MvPCS::verify(
        //     &self.key.get_snark_vk().mv_pcs_vk,
        //     last_accumulator,
        //     &proof.get_index(),
        //     &E::ScalarField::zero(),
        //     proof.get_value_opening_proof(),
        // )
        // .map_err(|_| VKDError::ClientError(errors::ClientError::SelfAuditFailed))?;

        // self.check_index(
        //     proof.get_label_opening_proof(),
        //     last_epoch_message
        //         .get_dictionary_commitment()
        //         .label_commitment(),
        //     &proof.get_index(),
        // )?;

        todo!();
        Ok(())
    }
}

impl<E, T, MvPCS> IronClient<E, T, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
    T: VKDLabel<E>,
{
}
