use crate::{
    pcs::{
        kzhk::{
            msm::msm_wrapper_g1,
            srs::{KZHKProverParam, KZHKUniversalParams, KZHKVerifierParam},
            structs::{KZHKAuxInfo, KZHKCommitment, KZHKOpeningProof},
        },
        PCSGlobalParam,
    },
    poly::{self, DenseOrSparseMLE},
    Commitment, PCSError, PolynomialCommitmentScheme, StructuredReferenceString,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::One;
use ark_poly::{
    univariate::DenseOrSparsePolynomial, DenseMultilinearExtension, MultilinearExtension,
    SparseMultilinearExtension,
};
use ark_serialize::CanonicalDeserialize;
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut, end_timer, log2,
    rand::{Rng, RngCore},
    start_timer, test_rng, Zero,
};
use smallvec::SmallVec;
use std::{
    borrow::Borrow,
    collections::BTreeMap,
    env::current_dir,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    marker::PhantomData,
};
use transcript::IOPTranscript;
pub mod msm;
pub mod srs;
pub mod structs;
use arithmetic::{
    bits_le_to_usize,
    multilinear_polynomial::{
        evaluate_last_sparse, fix_last_variables, fix_last_variables_boolean,
        fix_last_variables_boolean_sparse, fix_last_variables_sparse,
        partially_eval_dense_poly_on_bool_point, partially_eval_sparse_poly_on_bool_point,
        rand_sparse_mle,
    },
    virtual_polynomial::build_eq_x_r,
};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
mod test;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZHK<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
    k: usize,
}

impl<E> PolynomialCommitmentScheme<E> for KZHK<E>
where
    E: Pairing,
{
    type Config = usize;
    type ProverParam = KZHKProverParam<E>;
    type VerifierParam = KZHKVerifierParam<E>;
    type SRS = KZHKUniversalParams<E>;
    type Polynomial = DenseOrSparseMLE<E::ScalarField>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    type Commitment = KZHKCommitment<E>;
    type Proof = KZHKOpeningProof<E>;
    type BatchProof = KZHKOpeningProof<E>;
    type Aux = KZHKAuxInfo<E>;

    fn gen_srs_for_testing<R: Rng>(
        conf: Option<Self::Config>,
        rng: &mut R,
        supported_size: usize,
        zk: bool,
    ) -> Result<Self::SRS, PCSError> {
        let k = conf.unwrap_or_else(|| compute_k(supported_size, zk));
        let srs_path = current_dir()
            .unwrap()
            .join(format!("../srs/srs_{:?}_{}.bin", k, supported_size));
        let srs = if srs_path.exists() {
            eprintln!("Loading SRS");
            let mut buffer = Vec::new();
            BufReader::new(File::open(&srs_path).unwrap())
                .read_to_end(&mut buffer)
                .unwrap();
            Self::SRS::deserialize_uncompressed_unchecked(&buffer[..]).unwrap_or_else(|_| {
                panic!("Failed to deserialize SRS from {:?}", srs_path);
            })
        } else {
            eprintln!("Computing SRS");
            let mut rng = test_rng();
            let srs =
                KZHKUniversalParams::gen_srs_for_testing(&mut rng, k, zk, supported_size).unwrap();
            let mut serialized = Vec::new();
            srs.serialize_uncompressed(&mut serialized).unwrap();
            BufWriter::new(
                File::create(srs_path.clone())
                    .unwrap_or_else(|_| panic!("could not create file for SRS at {:?}", srs_path)),
            )
            .write_all(&serialized)
            .unwrap();
            srs
        };
        Ok(srs)
    }

    fn trim(
        srs: impl Borrow<Self::SRS>,
        _supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let srs = srs.borrow();
        let supp_nv = supported_num_vars.unwrap();
        assert_eq!(srs.get_dimensions().iter().sum::<usize>(), supp_nv);
        Ok((
            srs.extract_prover_param(supp_nv),
            srs.extract_verifier_param(supp_nv),
        ))
    }

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<(Self::Commitment, Self::Aux), PCSError> {
        let timer = start_timer!(|| "KZH::Commit");
        if !prover_param.borrow().is_zk() {
            return Ok(Self::commit_non_zk(prover_param, poly).unwrap());
        }
        let result = Ok(Self::commit_zk(prover_param, poly).unwrap());
        end_timer!(timer);
        result
    }

    fn update_aux(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        com: &Self::Commitment,
        aux: &mut Self::Aux,
    ) -> Result<(), PCSError> {
        Self::update_aux_inner(prover_param, polynomial, com, aux)
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        commitment: &Self::Commitment,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
        aux: &Self::Aux,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        let timer = start_timer!(|| "KZH::Open");
        let result = if !prover_param.borrow().is_zk() {
            Self::open_non_zk(prover_param, commitment, polynomial, point, aux)
        } else {
            Self::open_zk(prover_param, commitment, polynomial, point, aux, transcript)
        };

        end_timer!(timer);
        result
    }

    fn multi_open(
        prover_param: impl Borrow<Self::ProverParam>,
        commitment: &Self::Commitment,
        polynomials: &[&Self::Polynomial],
        point: &Self::Point,
        auxes: &[Self::Aux],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(Self::BatchProof, Self::Evaluation), PCSError> {
        Self::multi_open_non_zk(
            prover_param,
            commitment,
            polynomials,
            point,
            auxes,
            transcript,
        )
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        let timer = start_timer!(|| "KZH::Verify");
        let result = match (proof.get_r_hide(), proof.get_y_r(), proof.get_rho_prime()) {
            (Some(_), Some(_), Some(_)) => {
                Self::verify_zk(verifier_param, commitment, point, value, None, proof)
            },
            _ => Self::verify_non_zk(verifier_param, commitment, point, value, None, proof),
        };
        end_timer!(timer);
        result
    }

    fn batch_verify(
        verifier_param: &Self::VerifierParam,
        commitments: &[Self::Commitment],
        auxs: Option<&[Self::Aux]>,
        point: &Self::Point,
        values: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        Self::batch_verify_non_zk(
            verifier_param,
            commitments,
            auxs,
            point,
            values,
            batch_proof,
            transcript,
        )
    }
}

impl<E: Pairing> KZHK<E> {
    fn commit_zk(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        poly: &DenseOrSparseMLE<E::ScalarField>,
    ) -> Result<(KZHKCommitment<E>, KZHKAuxInfo<E>), PCSError> {
        let timer = start_timer!(|| "KZH::Commit-ZK");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let tau = E::ScalarField::rand(&mut test_rng());
        let (non_zk_com, _) = Self::commit_non_zk(prover_param, poly)?;
        let randomized_commitment =
            (non_zk_com.get_commitment().into_group() + prover_param.get_h() * tau).into_affine();
        let aux_info = KZHKAuxInfo::new(Some(tau), None);
        let result = Ok((
            KZHKCommitment::new(randomized_commitment, non_zk_com.get_num_vars()),
            aux_info,
        ));
        end_timer!(timer);
        result
    }

    fn commit_non_zk(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        poly: &DenseOrSparseMLE<E::ScalarField>,
    ) -> Result<(KZHKCommitment<E>, KZHKAuxInfo<E>), PCSError> {
        let timer = start_timer!(|| "KZH::Commit-Non-ZK");
        let non_zk_com = match poly {
            DenseOrSparseMLE::Dense(poly) => Self::commit_dense_inner(prover_param, poly),
            DenseOrSparseMLE::Sparse(poly) => Self::commit_sparse_inner(prover_param, poly),
        };
        let result = Ok((non_zk_com.unwrap(), KZHKAuxInfo::default()));
        end_timer!(timer);
        result
    }

    fn update_aux_inner(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseOrSparseMLE<E::ScalarField>,
        com: &KZHKCommitment<E>,
        aux: &mut KZHKAuxInfo<E>,
    ) -> Result<(), PCSError> {
        let timer = start_timer!(|| "KZH::CompAux");
        let result = match polynomial {
            DenseOrSparseMLE::Dense(poly) => Self::update_aux_dense(prover_param, poly, com, aux),
            DenseOrSparseMLE::Sparse(poly) => Self::update_aux_sparse(prover_param, poly, com, aux),
        };
        end_timer!(timer);
        result
    }

    fn open_non_zk(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        _commitment: &KZHKCommitment<E>,
        polynomial: &DenseOrSparseMLE<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open-Non-ZK");
        let is_boolean_point = point.iter().all(|&x| x.is_zero() || x.is_one());
        let result = match (is_boolean_point, polynomial) {
            (true, DenseOrSparseMLE::Dense(poly)) => {
                Self::open_dense_bool_inner(prover_param, poly, point, aux)
            },
            (true, DenseOrSparseMLE::Sparse(poly)) => {
                Self::open_sparse_bool_inner(prover_param, poly, point, aux)
            },
            (false, DenseOrSparseMLE::Dense(poly)) => {
                Self::open_dense_non_bool_inner(prover_param, poly, point, aux)
            },
            (false, DenseOrSparseMLE::Sparse(poly)) => {
                Self::open_sparse_non_bool_inner(prover_param, poly, point, aux)
            },
        };
        end_timer!(timer);
        result
    }

    fn open_zk(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        commitment: &KZHKCommitment<E>,
        polynomial: &DenseOrSparseMLE<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open-ZK");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        // The zk path
        let (non_zk_opening, non_zk_value) =
            Self::open_non_zk(prover_param, commitment, polynomial, point, aux)?;
        // Sampling the sparse polynomial r(X)
        let r_poly: SparseMultilinearExtension<E::ScalarField> = rand_sparse_mle(
            polynomial.num_vars(),
            prover_param.get_hiding_sparsity().unwrap(),
            &mut test_rng(),
        );
        let r_poly_wrapped = DenseOrSparseMLE::Sparse(r_poly.clone());
        // Committing to the r(X) polynomial
        let (r_hide, r_aux) = Self::commit(prover_param, &r_poly_wrapped)?;
        // Computing the auxiliary of r(x)
        // let _ = Self::update_aux_inner(prover_param, &r_poly_wrapped, &r_hide, &mut r_aux);
        let rho = r_aux.get_tau();
        // Computing the opening and evaluation of r(x)
        // let (r_opening, y_r) =
            // Self::open_non_zk(prover_param, commitment, &r_poly_wrapped, point, &r_aux)?;
        let dummy_aux = KZHKAuxInfo::default();
        let (r_opening, y_r) =
        Self::open_sparse_non_bool_inner(prover_param, &r_poly, point, &dummy_aux)?;
        // Getting the challenge alpha
        let alpha = E::ScalarField::one();
        // Computing rho_prime
        let rho_prime = alpha * aux.get_tau() + rho;
        let mut output_opening = non_zk_opening * alpha + r_opening;
        output_opening.set_r_hide(r_hide);
        output_opening.set_y_r(y_r);
        output_opening.set_rho_prime(rho_prime);
        let result = Ok((output_opening, non_zk_value));
        end_timer!(timer);
        result
    }

    // This impl is not safe, since it does not use random alphas for batching
    fn multi_open_non_zk(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        commitment: &KZHKCommitment<E>,
        polynomials: &[&DenseOrSparseMLE<E::ScalarField>],
        point: &Vec<E::ScalarField>,
        auxes: &[KZHKAuxInfo<E>],
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let num_vars = point.len();
        let mut aggr_aux: KZHKAuxInfo<E> = KZHKAuxInfo::default();
        let (agg_poly, aggr_aux) = match polynomials[0] {
            DenseOrSparseMLE::Dense(_) => {
                let mut aggr_poly = DenseMultilinearExtension::from_evaluations_vec(
                    num_vars,
                    vec![E::ScalarField::zero(); 1usize << num_vars],
                );
                for (poly, aux) in polynomials.iter().zip(auxes.iter()) {
                    if let DenseOrSparseMLE::Dense(dense_poly) = poly {
                        aggr_poly += dense_poly;
                        aggr_aux = aggr_aux + aux.clone();
                    } else {
                        panic!("All polynomials must be dense here");
                    }
                }
                (DenseOrSparseMLE::Dense(aggr_poly), aggr_aux)
            },
            DenseOrSparseMLE::Sparse(_) => {
                let mut aggr_poly =
                    SparseMultilinearExtension::from_evaluations(num_vars, Vec::new());
                for (poly, aux) in polynomials.iter().zip(auxes.iter()) {
                    if let DenseOrSparseMLE::Sparse(sparse_poly) = poly {
                        aggr_poly += sparse_poly;
                        aggr_aux = aggr_aux + aux.clone();
                    } else {
                        panic!("All polynomials must be sparse here");
                    }
                }

                (DenseOrSparseMLE::Sparse(aggr_poly), aggr_aux)
            },
        };
        Self::open_non_zk(prover_param, commitment, &agg_poly, point, &aggr_aux)
    }

    fn verify_zk(
        verifier_param: &KZHKVerifierParam<E>,
        commitment: &KZHKCommitment<E>,
        point: &[E::ScalarField],
        value: &E::ScalarField,
        _aux: Option<&KZHKAuxInfo<E>>,
        proof: &KZHKOpeningProof<E>,
    ) -> Result<bool, PCSError> {
        let timer = start_timer!(|| "KZH::Verify-ZK");
        let alpha = E::ScalarField::one();
        let c_lin = (commitment.get_commitment().into_group() * alpha
            + proof.get_r_hide().unwrap().get_commitment().into_group()
            - verifier_param.get_h() * proof.get_rho_prime().unwrap())
        .into_affine();
        let lin_commitment = KZHKCommitment::new(c_lin, commitment.get_num_vars());
        let lin_value = *value * alpha + proof.get_y_r().unwrap();
        let result = Self::verify_non_zk(
            verifier_param,
            &lin_commitment,
            point,
            &lin_value,
            None,
            proof,
        );
        end_timer!(timer);
        result
    }

    fn verify_non_zk(
        verifier_param: &KZHKVerifierParam<E>,
        commitment: &KZHKCommitment<E>,
        point: &[E::ScalarField],
        value: &E::ScalarField,
        _aux: Option<&KZHKAuxInfo<E>>,
        proof: &KZHKOpeningProof<E>,
    ) -> Result<bool, PCSError> {
        let timer = start_timer!(|| "KZH::Verify-Non-ZK");
        let k = verifier_param.get_dimensions().len();
        let mut cj = commitment.get_commitment();
        let decomposed_point = KZHK::<E>::decompose_point(verifier_param.get_dimensions(), point);
        let pairing_loop_timer = start_timer!(|| "KZH::Verify::PairingLoop");

        // TODO: See if it's worth it to randomely combine all multi-pairings
        for (j, point_part) in decomposed_point.iter().take(k - 1).enumerate() {
            let cj_prepared = <E as Pairing>::G1Prepared::from(cj);
            let minus_v_prepared = <E as Pairing>::G2Prepared::from(verifier_param.get_minus_v());

            let mut g1_terms = Vec::with_capacity(1 + proof.get_d()[j].len());
            let mut g2_terms = Vec::with_capacity(1 + verifier_param.get_v_mat()[j].len());

            g1_terms.push(cj_prepared);
            g2_terms.push(minus_v_prepared.clone());

            g1_terms.extend(
                proof.get_d()[j]
                    .iter()
                    .copied()
                    .map(<E as Pairing>::G1Prepared::from),
            );
            g2_terms.extend(verifier_param.get_v_mat()[j].iter().cloned());

            let prod = E::multi_pairing(g1_terms, g2_terms);
            debug_assert!(prod.is_zero());

            let eq_poly = build_eq_x_r(point_part).unwrap();
            cj = msm_wrapper_g1::<E>(&proof.get_d()[j], &eq_poly.evaluations).into_affine();
        }
        end_timer!(pairing_loop_timer);
        // Checking c_{k-1}
        let cj_check_timer = start_timer!(|| "KZH::Verify::CJCheck");
        let alleged_last_cj = E::G1::msm(
            verifier_param
                .get_h_tensor()
                .as_slice_memory_order()
                .unwrap(),
            &proof.get_f().to_evaluations(),
        )
        .unwrap()
        .into_affine();
        assert_eq!(cj, alleged_last_cj);
        end_timer!(cj_check_timer);
        // Evaluation Check
        let eval_check_timer = start_timer!(|| "KZH::Verify::EvalCheck");
        let p = match proof.get_f() {
            DenseOrSparseMLE::Dense(f) => {
                fix_last_variables(f, &decomposed_point[k - 1])[0] == *value
            },
            DenseOrSparseMLE::Sparse(f) => {
                fix_last_variables_sparse(f, &decomposed_point[k - 1])[0] == *value
            },
        };
        end_timer!(eval_check_timer);
        end_timer!(timer);
        Ok(true)
    }

    fn batch_verify_non_zk(
        verifier_param: &KZHKVerifierParam<E>,
        commitments: &[KZHKCommitment<E>],
        auxs: Option<&[KZHKAuxInfo<E>]>,
        point: &Vec<E::ScalarField>,
        values: &[E::ScalarField],
        batch_proof: &KZHKOpeningProof<E>,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        let mut aggr_comm = KZHKCommitment::default();
        let mut aggr_value = E::ScalarField::zero();
        for ((comm, aux), value) in commitments.iter().zip(auxs.iter()).zip(values.iter()) {
            aggr_comm = aggr_comm + *comm;
            aggr_value += value;
        }

        Self::verify(
            verifier_param,
            &aggr_comm,
            point,
            &aggr_value,
            batch_proof,
            _transcript,
        )
    }

    fn commit_dense_inner(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        poly: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZHKCommitment<E>, PCSError> {
        let commit_timer = start_timer!(|| "KZH::Commit_Dense");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let com = msm_wrapper_g1::<E>(
            prover_param.get_h_tensors()[0]
                .as_slice_memory_order()
                .unwrap(),
            &poly.evaluations,
        );
        end_timer!(commit_timer);
        Ok(KZHKCommitment::new(com.into(), poly.num_vars()))
    }

    fn commit_sparse_inner(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        sparse_poly: &SparseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZHKCommitment<E>, PCSError> {
        let commit_timer = start_timer!(|| "KZH::Commit_Sparse");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        // The scalars for the MSM are the values from the sparse polynomial's
        // evaluation map.
        let scalars: Vec<E::ScalarField> = sparse_poly.evaluations.values().cloned().collect();
        // The bases for the MSM must correspond to the generator at the index
        // specified by the key in the sparse polynomial's evaluation map.
        let h_mat = prover_param.get_h_tensors()[0]
            .as_slice_memory_order()
            .unwrap();
        let bases: Vec<E::G1Affine> = sparse_poly
        .evaluations
        .keys()
        .map(|&index| h_mat[index]) // Use the key `index` to get the correct base.
        .collect();

        let com = msm_wrapper_g1::<E>(&bases, &scalars);
        end_timer!(commit_timer);
        Ok(KZHKCommitment::new(
            com.into_affine(),
            sparse_poly.num_vars(),
        ))
    }

    fn update_aux_dense(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        _com: &KZHKCommitment<E>,
        aux: &mut KZHKAuxInfo<E>,
    ) -> Result<(), PCSError> {
        let timer = start_timer!(|| "KZH::CompAux_Dense");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let dimensions = prover_param.get_dimensions();
        let k = dimensions.len();
        debug_assert!(k >= 2, "need at least 2 blocks to build d_i's");

        let mut d_bool: Vec<Vec<E::G1Affine>> = Vec::with_capacity(k - 1);
        let mut prefix_vars: usize = 0;

        for (j, &dim) in dimensions.iter().take(k - 1).enumerate() {
            // Update prefix sum of variables up to and including block j
            prefix_vars += dim;

            // Number of i's (outer loop) and length of each partial evaluation
            let dj_size = 1usize << prefix_vars;
            let rem_vars = polynomial.num_vars() - prefix_vars;
            let eval_len = 1usize << rem_vars;

            // Choose H_t. Natural generalization uses [j]; if you intended to always use
            // [0], replace `j` with `0` below.
            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous (standard layout)");

            // Build d_{j}
            // TODO: Why can't we use d_j.par_iter_mut()?
            let mut d_j = vec![E::G1Affine::zero(); dj_size];
            cfg_iter_mut!(d_j).enumerate().for_each(|(i, d_j_i)| {
                let scalars = partially_eval_dense_poly_on_bool_point(polynomial, i, eval_len);
                *d_j_i = msm_wrapper_g1::<E>(h_slice, scalars.as_slice()).into_affine()
            });

            d_bool.push(d_j);
        }
        aux.set_d_bool(d_bool);
        end_timer!(timer);
        Ok(())
    }

    fn update_aux_sparse(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        _com: &KZHKCommitment<E>,
        aux: &mut KZHKAuxInfo<E>,
    ) -> Result<(), PCSError> {
        let timer = start_timer!(|| "KZH::CompAux_Sparse");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let dimensions = prover_param.get_dimensions();
        let k = dimensions.len();
        debug_assert!(k >= 2, "need at least 2 blocks to build d_i's");

        // Build prefix sums of dimensions up to each block (exclusive of the last)
        let prefix_timer = start_timer!(|| "KZH::CompAux_Sparse::PrefixSums");
        let prefix_vars_vec: Vec<usize> = {
            let mut prefix_vars: usize = 0;
            dimensions
                .iter()
                .take(k - 1)
                .map(|&dim| {
                    prefix_vars += dim;
                    prefix_vars
                })
                .collect()
        };
        end_timer!(prefix_timer);

        // Compute d_bool without shared mutation; preserve order across j.
        let d_bool_timer = start_timer!(|| "KZH::CompAux_Sparse::D_Bool");
        let d_bool: Vec<Vec<E::G1Affine>> = {
            cfg_into_iter!(0..k - 1)
                .map(|j| {
                    let prefix_var = prefix_vars_vec[j];
                    // Number of i's (outer loop) and length of each partial evaluation
                    let dj_size = 1usize << prefix_var;
                    let rem_vars = polynomial.num_vars() - prefix_var;
                    let eval_len = 1usize << rem_vars;

                    // Choose H_t. Natural generalization uses [j]; if you intended to always
                    // use [0], replace j with 0 below.
                    let h_slice = prover_param.get_h_tensors()[j + 1]
                        .as_slice_memory_order()
                        .expect("H_t must be contiguous (standard layout)");

                    // Build d_{j}
                    let mut d_j = vec![E::G1Affine::zero(); dj_size];
                    d_j.iter_mut().enumerate().for_each(|(i, d_j_i)| {
                        let scalars_map =
                            partially_eval_sparse_poly_on_bool_point(polynomial, i, eval_len);
                        let mut bases = Vec::new();
                        let mut scalars = Vec::new();
                        for (local_idx, s) in scalars_map {
                            bases.push(h_slice[local_idx]);
                            scalars.push(*s);
                        }

                        *d_j_i = if scalars.is_empty() {
                            E::G1Affine::zero()
                        } else {
                            msm_wrapper_g1::<E>(&bases, &scalars).into_affine()
                        };
                    });
                    d_j
                })
                .collect()
        };
        end_timer!(d_bool_timer);

        aux.set_d_bool(d_bool);
        end_timer!(timer);
        Ok(())
    }

    fn open_dense_non_bool_inner(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        _aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Dense");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let mut d = Vec::new();
        let k = prover_param.get_dimensions().len();
        let decomposed_point = KZHK::<E>::decompose_point(prover_param.get_dimensions(), point);
        let mut partial_polynomial = polynomial.clone();
        for (j, point_part) in decomposed_point.iter().take(k - 1).enumerate() {
            let partial_polynomial_evals = &partial_polynomial.evaluations;
            // Now start iterating over the boolean partial evaluations
            let num_chunks = 1 << prover_param.get_dimensions()[j];
            assert_eq!(partial_polynomial_evals.len() % num_chunks, 0);
            let chunk_len: usize = partial_polynomial_evals.len() / num_chunks; // = 2^(n-r)
            debug_assert!(chunk_len > 0);
            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous");
            // immutable
            let dj: Vec<E::G1Affine> = cfg_into_iter!(0..num_chunks)
                .map(|i| {
                    let off = i * chunk_len;
                    let chunk = &partial_polynomial_evals[off..off + chunk_len];
                    msm_wrapper_g1::<E>(h_slice, chunk).into_affine()
                })
                .collect();
            d.push(dj);

            partial_polynomial = fix_last_variables(&partial_polynomial, point_part);
        }
        let f = DenseOrSparseMLE::Dense(partial_polynomial.clone());
        let eval = fix_last_variables(&partial_polynomial, &decomposed_point[k - 1])[0];
        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f, None, None, None), eval))
    }

    fn open_dense_bool_inner(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Dense_Boolean");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();

        let aux_d_bool = aux.get_d_bool();
        let mut d: Vec<Vec<E::G1Affine>> = Vec::new();

        let dims = prover_param.get_dimensions();
        let k = dims.len();

        let decomposed_point = KZHK::<E>::decompose_point(dims, point);
        let mut partial_polynomial = polynomial.clone();

        // Track the integer encoding of the already-fixed (prefix) boolean blocks,
        // little-endian.
        let mut eb: usize = 0;

        for (j, partial_point) in decomposed_point.iter().take(k - 1).enumerate() {
            let block_dim = dims[j];
            let start = eb << block_dim; // == eb * 2^{block_dim}
            let end = start + (1 << block_dim);

            let aux_vec = &aux_d_bool[j];
            debug_assert!(end <= aux_vec.len(), "aux slice OOB");

            // Parallel clone of the aux slice -> d_j
            let d_j: Vec<E::G1Affine> = cfg_iter!(aux_vec[start..end]).cloned().collect();

            d.push(d_j);

            // Reduce the dense polynomial on this boolean block (sequential dependency)
            partial_polynomial = fix_last_variables_boolean(&partial_polynomial, partial_point);

            // Update eb to include this block for the next iteration:
            // new_bits = [partial_point || old_bits] (LE), so:
            // eb_next = bits_le(partial_point) + (eb << block_dim)
            let s = bits_le_to_usize(partial_point);
            eb = s + (eb << block_dim);
        }

        let f = DenseOrSparseMLE::Dense(partial_polynomial.clone());
        let eval = fix_last_variables_boolean(&partial_polynomial, &decomposed_point[k - 1])[0];

        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f, None, None, None), eval))
    }
    fn open_sparse_non_bool_inner(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        _aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Sparse");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let mut d = Vec::new();
        let k = prover_param.get_dimensions().len();
        let decomposed_point = KZHK::<E>::decompose_point(prover_param.get_dimensions(), point);
        let mut partial_polynomial = polynomial.clone();

        for (j, point_part) in decomposed_point.iter().take(k - 1).enumerate() {
            // Same partitioning as dense:
            let num_chunks = 1usize << prover_param.get_dimensions()[j]; // 2^{block_j}
            let chunk_len =
                1usize << (partial_polynomial.num_vars - prover_param.get_dimensions()[j]); // 2^{remaining - block_j}
            let domain_len = 1usize << partial_polynomial.num_vars;
            debug_assert_eq!((num_chunks * chunk_len), domain_len);

            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous");
            debug_assert_eq!(h_slice.len(), chunk_len);

            // Iterate windows in increasing "x-index" order (matches dense & verifier eq
            // order)
            let mut dj = vec![E::G1Affine::zero(); num_chunks];
            cfg_iter_mut!(dj).enumerate().for_each(|(i, d_j_i)| {
                let base = i * chunk_len;
                // Gather non-zeros in [base, base+chunk_len) and rebase to local [0..chunk_len)
                let mut bases = Vec::new();
                let mut scalars = Vec::new();
                for (&gidx, &val) in partial_polynomial.evaluations.range(base..base + chunk_len) {
                    let local = gidx - base;
                    bases.push(h_slice[local]);
                    scalars.push(val);
                }
                let acc = if scalars.is_empty() {
                    E::G1Affine::zero()
                } else {
                    msm_wrapper_g1::<E>(&bases, &scalars).into_affine()
                };
                *d_j_i = acc;
            });
            d.push(dj);

            // Reduce the last block by the point part (must match dense orientation)
            partial_polynomial = fix_last_variables_sparse(&partial_polynomial, point_part);
        }

        let f = DenseOrSparseMLE::Sparse(partial_polynomial.clone());
        let eval = fix_last_variables_sparse(&partial_polynomial, &decomposed_point[k - 1])[0];
        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f, None, None, None), eval))
    }

    fn open_sparse_bool_inner(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Sparse_Boolean");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let dims = prover_param.get_dimensions();
        let k = dims.len();

        let aux_d_bool = aux.get_d_bool();
        let decomposed_point = KZHK::<E>::decompose_point(dims, point);

        let mut d: Vec<Vec<E::G1Affine>> = Vec::with_capacity(k - 1);
        let mut partial_polynomial = polynomial.clone();

        // eb encodes the already-fixed boolean prefix in little-endian
        let mut eb: usize = 0;

        for (j, partial_point) in decomposed_point.iter().take(k - 1).enumerate() {
            let block_dim = dims[j];
            let start = eb << block_dim; // == eb * 2^{block_dim}
            let end = start + (1 << block_dim);

            let aux_vec = &aux_d_bool[j];
            debug_assert!(end <= aux_vec.len(), "aux slice OOB");

            // Parallel clone of aux slice -> d_j
            let d_j: Vec<E::G1Affine> = cfg_iter!(aux_vec[start..end]).cloned().collect();

            d.push(d_j);

            // Reduce the last block on the sparse polynomial (sequential dependency)
            partial_polynomial =
                fix_last_variables_boolean_sparse(&partial_polynomial, partial_point);

            // Update eb to include this block for next iteration:
            // new_bits = [partial_point || old_bits] (LE)
            let s = bits_le_to_usize(partial_point);
            eb = s + (eb << block_dim);
        }

        let f = DenseOrSparseMLE::Sparse(partial_polynomial.clone());
        let eval =
            fix_last_variables_boolean_sparse(&partial_polynomial, &decomposed_point[k - 1])[0];

        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f, None, None, None), eval))
    }

    fn decompose_point(dimensions: &[usize], point: &[E::ScalarField]) -> Vec<Vec<E::ScalarField>> {
        let mut decomposed = Vec::new();
        let mut start = 0;
        for &dim in dimensions {
            let end = start + dim;
            decomposed.push(point[start..end].to_vec());
            start = end;
        }
        decomposed
    }
}

/// Cross‑compat “for_each_with_scratch”: uses `for_each_init` in parallel
/// builds, and a single reusable scratch in sequential builds.
#[macro_export]
macro_rules! cfg_for_each_with_scratch {
    ($iter:expr, $make_scratch:expr, |$scratch:ident, $item:pat_param| $body:block) => {{
        #[cfg(feature = "parallel")]
        {
            ($iter).for_each_init($make_scratch, |$scratch, $item| $body);
        }
        #[cfg(not(feature = "parallel"))]
        {
            let mut $scratch = $make_scratch();
            for $item in $iter {
                $body
            }
        }
    }};
}
// TODO: Check if this is optimum
pub fn compute_k(poly_size: usize, is_zk: bool) -> usize {
    let n: u128 = 1 << poly_size;
    // if is_zk {
        // (0.5 * (n as f64).ln()) as usize
    // } else {
        poly_size
    // }
}
