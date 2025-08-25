pub(crate) mod errors;
#[cfg(test)]
mod tests;
use crate::{
    VKDDictionary, VKDKey, VKDLabel, VKDPublicParameters, VKDResult, VKDServer,
    bb::{
        BulletinBoard,
        dummybb::{DummyBB, IronEpochMessage},
    },
    structs::{
        dictionary::IronDictionary,
        lookup::IronLookupProof,
        pp::{IronPublicParameters, IronServerKey},
        self_audit::IronSelfAuditProof,
        update::{IronEpochKeyMessage, IronEpochRegMessage, IronUpdateProof},
    },
};
use arithmetic::{
    multilinear_polynomial::evaluate_last_sparse, virtual_polynomial::VirtualPolynomial,
};
use ark_ec::pairing::Pairing;
use ark_poly::MultilinearExtension;
use ark_std::{One, Zero, end_timer, start_timer, test_rng};
#[cfg(feature = "parallel")]
use rayon::join;
use std::{
    collections::HashMap,
    ops::{Add, Sub},
    sync::Arc,
};
use subroutines::{PolyIOP, PolynomialCommitmentScheme, ZeroCheck, poly::DenseOrSparseMLE};
pub struct IronServer<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
    T: VKDLabel<E>,
> {
    dictionary: IronDictionary<E, T>,
    key: IronServerKey<E, MvPCS>,
    pub label_aux: MvPCS::Aux,
    pub value_aux: MvPCS::Aux,
    pub diff_aux: MvPCS::Aux,
}

impl<E, MvPCS, T> VKDServer<E, MvPCS> for IronServer<E, MvPCS, T>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
            Evaluation = E::ScalarField,
        > + Sync
        + Send,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    T: VKDLabel<E>,
{
    type UpdateBatch = HashMap<T, E::ScalarField>;
    type StateCommitment = MvPCS::Commitment;
    type Dictionary = IronDictionary<E, T>;
    type LookupProof = IronLookupProof<E, MvPCS>;
    type UpdateProof = IronUpdateProof<E, MvPCS>;
    type SelfAuditProof = IronSelfAuditProof<E, MvPCS>;
    type PublicParameters = IronPublicParameters<E, MvPCS>;
    type ServerKey = IronServerKey<E, MvPCS>;
    type BulletinBoard = DummyBB<E, MvPCS>;

    fn init(pp: &Self::PublicParameters) -> Self {
        Self {
            dictionary: IronDictionary::new_with_capacity(pp.get_specification().get_capacity()),
            key: pp.to_server_key(),
            label_aux: MvPCS::Aux::default(),
            value_aux: MvPCS::Aux::default(),
            diff_aux: MvPCS::Aux::default(),
        }
    }

    fn update_reg(
        &mut self,
        update_batch: &Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()>
    where
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    {
        #[cfg(test)]
        {
            self.authenticate_batch(update_batch)?;
        }
        // Save the current label MLE
        let current_label_mle = self.dictionary.get_label_mle().clone();
        // Insert the batch to the dictionary
        self.dictionary.insert_batch(update_batch)?;
        // Now save the new label MLE
        let new_label_mle = self.dictionary.get_label_mle();
        // Compute the difference MLE
        let diff_label_mle: DenseOrSparseMLE<<E as Pairing>::ScalarField> =
            &*new_label_mle.borrow() - &*current_label_mle.borrow();
        // Commit to the diff commitment
        let mut rng = test_rng();

        let (diff_label_com, mut diff_label_aux) =
            MvPCS::commit(self.key.get_pcs_prover_param(), &diff_label_mle).unwrap();
        // Compute the diff aux
        MvPCS::update_aux(
            self.key.get_pcs_prover_param(),
            &diff_label_mle,
            &diff_label_com,
            &mut diff_label_aux,
        )
        .unwrap();
        // Check if the bulletin board has a reg message
        let iron_epoch_reg_message = match bulletin_board.get_last_reg_update_message() {
            // If it's the first time, the diff info is the new info
            None => {
                self.label_aux = diff_label_aux;
                // Send the commitment
                IronEpochRegMessage::new(diff_label_com, None)
            },
            // If it's not the first time, we need to do a zerocheck
            Some(last_reg_message) => {
                // Get the last label commitment
                let last_label_comm = last_reg_message.get_label_commitment();
                // Get the last label aux
                let last_label_aux = &self.label_aux;
                // The new commitment is the last one plus the diff
                let new_label_comm = last_label_comm.clone() + diff_label_com;
                // The new aux is the last one plus the diff
                let new_label_aux = last_label_aux.clone() + diff_label_aux;
                // Intiate the transcipt for the zerocheck
                let mut transcript =
                    <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::init_transcript();
                transcript.append_message(b"iron-key", b"iron-key").unwrap();
                // Build the target virtual polynomial to do the zerocheck on
                let mut target_virtual_poly =
                    VirtualPolynomial::new(current_label_mle.borrow().num_vars());
                // Building the target virtual polynomial
                // TODO: Make this zerocheck to operate on sparse polynomials
                let current_label_mle_arc = Arc::new(current_label_mle.borrow().to_dense());
                let new_label_mle_arc = Arc::new(new_label_mle.borrow().to_dense());
                target_virtual_poly
                    .add_mle_list(
                        [current_label_mle_arc.clone(), current_label_mle_arc.clone()],
                        E::ScalarField::one(),
                    )
                    .unwrap();
                target_virtual_poly
                    .add_mle_list(
                        [current_label_mle_arc, new_label_mle_arc],
                        -E::ScalarField::one(),
                    )
                    .unwrap();
                // Performing the zerocheck
                let zerocheck_proof =
                    <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(
                        &target_virtual_poly,
                        &mut transcript,
                    )
                    .unwrap();
                // Gathering the polynomials and auxes for opening the polynomials
                let polys = &[&*new_label_mle.borrow(), &*current_label_mle.borrow()];
                let auxes = vec![new_label_aux.clone(), last_label_aux.clone()];
                let update_proof = MvPCS::multi_open(
                    self.key.get_pcs_prover_param(),
                    &new_label_comm,
                    polys,
                    &zerocheck_proof.point,
                    &auxes,
                    &mut transcript,
                );
                let new_reg_eval = evaluate_last_sparse(
                    &new_label_mle.borrow().to_sparse(),
                    &zerocheck_proof.point,
                );
                let current_reg_eval = evaluate_last_sparse(
                    &current_label_mle.borrow().to_sparse(),
                    &zerocheck_proof.point,
                );
                let iron_update_proof: IronUpdateProof<E, MvPCS> = IronUpdateProof::new(
                    zerocheck_proof,
                    target_virtual_poly.aux_info.clone(),
                    new_reg_eval,
                    current_reg_eval,
                    update_proof.unwrap().0,
                );
                self.label_aux = new_label_aux;
                IronEpochRegMessage::new(new_label_comm, Some(iron_update_proof))
            },
        };

        let iron_epoch_message = IronEpochMessage::IronEpochRegMessage(iron_epoch_reg_message);
        bulletin_board.broadcast(iron_epoch_message)?;
        Ok(())
    }

    fn update_keys(
        &mut self,
        update_batch: &Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()>
    where
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    {
        #[cfg(test)]
        {
            self.authenticate_batch(update_batch)?;
        }
        let mut rng = test_rng();
        // Save the current value MLE
        let current_value_mle = self.dictionary.get_value_mle().clone();
        // Insert the batch to the dictionary
        self.dictionary.insert_batch(update_batch)?;
        // Now save the new value MLE
        let new_value_mle = self.dictionary.get_value_mle().clone();
        // Compute the difference MLE
        let diff_value_mle = &*new_value_mle.borrow() - &*current_value_mle.borrow();
        // Compute the commtment and the aux to the diff
        let (diff_value_com, mut diff_value_aux) =
            MvPCS::commit(self.key.get_pcs_prover_param(), &diff_value_mle).unwrap();
        MvPCS::update_aux(
            self.key.get_pcs_prover_param(),
            &diff_value_mle,
            &MvPCS::Commitment::default(),
            &mut diff_value_aux,
        )
        .unwrap();

        // Check if the bulletin board has a key message
        let iron_epoch_key_message = match bulletin_board.get_last_key_update_message() {
            // If it's the first time, the diff info is the new info
            None => {
                self.value_aux = diff_value_aux.clone();
                IronEpochKeyMessage::new(diff_value_com.clone(), diff_value_com)
            },
            // If there's already a key message, we need to accumulate the diff to the rlc
            // polynomial
            Some(last_key_message) => {
                let last_value_comm = last_key_message.get_value_commitment();
                let new_value_comm = last_value_comm.clone() + diff_value_com.clone();
                let new_value_aux = self.value_aux.clone() + diff_value_aux.clone();
                let last_diff_accumulator = last_key_message.get_difference_accumulator();
                let difference_accumulator = last_diff_accumulator.clone() + diff_value_com;
                let difference_aux = self.diff_aux.clone() + diff_value_aux;
                self.value_aux = new_value_aux;
                self.diff_aux = difference_aux;
                IronEpochKeyMessage::new(new_value_comm, difference_accumulator)
            },
        };

        let iron_epoch_message = IronEpochMessage::IronEpochKeyMessage(iron_epoch_key_message);
        // Serialize the epoch message and broadcast it to the bulletin board
        bulletin_board.broadcast(iron_epoch_message)?;
        Ok(())
    }

    fn lookup_prove(
        &self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<Self::LookupProof> {
        let timer = start_timer!(|| "IronServer::lookup_prove");
        let timer_index = start_timer!(|| "IronServer::lookup_prove::find_index");
        let index = self.dictionary.find_index(&label).unwrap();
        end_timer!(timer_index);
        let timer_get_message = start_timer!(|| "IronServer::lookup_prove::get_message");
        end_timer!(timer_get_message);
        let timer_index_boolean = start_timer!(|| "IronServer::lookup_prove::index_boolean");
        let index_boolean = Self::usize_to_field_bits(index, self.dictionary.log_max_size());
        end_timer!(timer_index_boolean);
        let timer_get_mle = start_timer!(|| "IronServer::lookup_prove::get_mle");
        let binding = self.dictionary.get_label_mle();
        let label_ref = binding.borrow();
        let binding = self.dictionary.get_value_mle();
        let value_ref = binding.borrow();
        end_timer!(timer_get_mle);
        let timer_open = start_timer!(|| "IronServer::lookup_prove::open");
        let mut transcript = PolyIOP::<E::ScalarField>::init_transcript();
        let label_opening_proof = MvPCS::open(
            self.key.get_pcs_prover_param(),
            &MvPCS::Commitment::default(),
            &*label_ref,
            &index_boolean,
            &self.label_aux,
            &mut transcript,
        )
        .unwrap();
        let value_opening_proof = MvPCS::open(
            self.key.get_pcs_prover_param(),
            &MvPCS::Commitment::default(),
            &*value_ref,
            &index_boolean,
            &self.value_aux,
            &mut transcript,
        )
        .unwrap();
        end_timer!(timer_open);
        end_timer!(timer);
        Ok(IronLookupProof::new(
            index_boolean,
            label_opening_proof,
            value_opening_proof,
        ))
    }

    fn self_audit_prove(
        &self,
        _label: <Self::Dictionary as VKDDictionary<E>>::Label,
    ) -> VKDResult<Self::SelfAuditProof> {
        todo!()
    }
}

impl<E, MvPCS, T> IronServer<E, MvPCS, T>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
    T: VKDLabel<E>,
{
    #[cfg(test)]
    fn authenticate_batch(&self, update_batch: &HashMap<T, E::ScalarField>) -> VKDResult<()> {
        use errors::ServerError;

        use crate::errors::VKDError;

        let timer = start_timer!(|| "IronServer::authenticate_batch");
        let res = update_batch
            .iter()
            .any(|(label, _)| self.dictionary.contains(label));
        end_timer!(timer);
        if res {
            Err(VKDError::ServerError(ServerError::AlreadyRegistered))
        } else {
            Ok(())
        }
    }

    fn usize_to_field_bits(mut value: usize, k: usize) -> Vec<E::ScalarField> {
        let mut bits = vec![E::ScalarField::zero(); k];
        for i in 0..k {
            bits[k - 1 - i] = if value & 1 == 1 {
                E::ScalarField::one()
            } else {
                E::ScalarField::zero()
            };
            value >>= 1;
        }
        bits
    }
}
