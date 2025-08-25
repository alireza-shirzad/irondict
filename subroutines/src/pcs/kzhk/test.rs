use super::*;
use ark_bn254::{Bn254 as E, Fr};
use ark_std::{test_rng, vec::Vec, UniformRand};

fn test_single_helper(
    nv: usize,
    zk: bool,
    is_sparse: bool,
    is_boolean: bool,
    k: usize,
) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let poly = if is_sparse {
        DenseOrSparseMLE::Sparse(SparseMultilinearExtension::<Fr>::rand(nv, &mut rng))
    } else {
        DenseOrSparseMLE::Dense(DenseMultilinearExtension::<Fr>::rand(nv, &mut rng))
    };
    let mut prover_transcript = IOPTranscript::new(b"test_kzhk");
    let params = KZHK::<E>::gen_srs_for_testing(Some(k), &mut rng, nv, zk)?;
    let (ck, vk) = KZHK::trim(params, None, Some(nv))?;
    let point = match is_boolean {
        true => (0..nv)
            .map(|_| Fr::from((usize::rand(&mut rng) % 2) as i64))
            .collect::<Vec<_>>(),
        false => (0..nv).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>(),
    };
    let (com, mut aux) = KZHK::<E>::commit(&ck, &poly)?;
    KZHK::<E>::update_aux(&ck, &poly, &com, &mut aux)?;
    let (proof, value) = KZHK::<E>::open(
        &ck,
        &com,
        &poly,
        &point,
        &aux,
        &mut prover_transcript,
    )?;
    let mut verif_transcript = IOPTranscript::new(b"test_kzhk");
    assert!(KZHK::<E>::verify(
        &vk,
        &com,
        &point,
        &value,
        &proof,
        &mut verif_transcript,
    )?);

    Ok(())
}
#[test]
fn test_dense_k2() -> Result<(), PCSError> {
    test_single_helper(2, false, false, false, 2)?;
    test_single_helper(3, false, false, false, 2)?;
    test_single_helper(4, false, false, false, 2)?;
    test_single_helper(5, false, false, false, 2)?;
    test_single_helper(6, false, false, false, 2)?;
    test_single_helper(7, false, false, false, 2)?;
    test_single_helper(8, false, false, false, 2)?;
    test_single_helper(9, false, false, false, 2)?;
    test_single_helper(10, false, false, false, 2)?;
    test_single_helper(11, false, false, false, 2)?;
    test_single_helper(12, false, false, false, 2)?;
    test_single_helper(13, false, false, false, 2)?;
    test_single_helper(14, false, false, false, 2)?;
    test_single_helper(15, false, false, false, 2)?;
    Ok(())
}

#[test]
fn test_dense_zk_k2() -> Result<(), PCSError> {
    test_single_helper(2, true, false, false, 2)?;
    test_single_helper(3, true, false, false, 2)?;
    test_single_helper(4, true, false, false, 2)?;
    test_single_helper(5, true, false, false, 2)?;
    test_single_helper(6, true, false, false, 2)?;
    test_single_helper(7, true, false, false, 2)?;
    test_single_helper(8, true, false, false, 2)?;
    test_single_helper(9, true, false, false, 2)?;
    test_single_helper(10, true, false, false, 2)?;
    test_single_helper(11, true, false, false, 2)?;
    test_single_helper(12, true, false, false, 2)?;
    test_single_helper(13, true, false, false, 2)?;
    test_single_helper(14, true, false, false, 2)?;
    test_single_helper(15, true, false, false, 2)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k2() -> Result<(), PCSError> {
    test_single_helper(2, false, false, true, 2)?;
    test_single_helper(3, false, false, true, 2)?;
    test_single_helper(4, false, false, true, 2)?;
    test_single_helper(5, false, false, true, 2)?;
    test_single_helper(6, false, false, true, 2)?;
    test_single_helper(7, false, false, true, 2)?;
    test_single_helper(8, false, false, true, 2)?;
    test_single_helper(9, false, false, true, 2)?;
    test_single_helper(10, false, false, true, 2)?;
    test_single_helper(11, false, false, true, 2)?;
    test_single_helper(12, false, false, true, 2)?;
    test_single_helper(13, false, false, true, 2)?;
    test_single_helper(14, false, false, true, 2)?;
    test_single_helper(15, false, false, true, 2)?;
    Ok(())
}

#[test]
fn test_dense_boolean_zk_k2() -> Result<(), PCSError> {
    test_single_helper(2, true, false, true, 2)?;
    test_single_helper(3, true, false, true, 2)?;
    test_single_helper(4, true, false, true, 2)?;
    test_single_helper(5, true, false, true, 2)?;
    test_single_helper(6, true, false, true, 2)?;
    test_single_helper(7, true, false, true, 2)?;
    test_single_helper(8, true, false, true, 2)?;
    test_single_helper(9, true, false, true, 2)?;
    test_single_helper(10, true, false, true, 2)?;
    test_single_helper(11, true, false, true, 2)?;
    test_single_helper(12, true, false, true, 2)?;
    test_single_helper(13, true, false, true, 2)?;
    test_single_helper(14, true, false, true, 2)?;
    test_single_helper(15, true, false, true, 2)?;
    Ok(())
}

#[test]
fn test_sparse_k2() -> Result<(), PCSError> {
    test_single_helper(2, false, true, false, 2)?;
    test_single_helper(3, false, true, false, 2)?;
    test_single_helper(4, false, true, false, 2)?;
    test_single_helper(5, false, true, false, 2)?;
    test_single_helper(6, false, true, false, 2)?;
    test_single_helper(7, false, true, false, 2)?;
    test_single_helper(8, false, true, false, 2)?;
    test_single_helper(9, false, true, false, 2)?;
    test_single_helper(10, false, true, false, 2)?;
    test_single_helper(11, false, true, false, 2)?;
    test_single_helper(12, false, true, false, 2)?;
    test_single_helper(13, false, true, false, 2)?;
    test_single_helper(14, false, true, false, 2)?;
    test_single_helper(15, false, true, false, 2)?;
    Ok(())
}

#[test]
fn test_sparse_zk_k2() -> Result<(), PCSError> {
    test_single_helper(2, true, true, false, 2)?;
    test_single_helper(3, true, true, false, 2)?;
    test_single_helper(4, true, true, false, 2)?;
    test_single_helper(5, true, true, false, 2)?;
    test_single_helper(6, true, true, false, 2)?;
    test_single_helper(7, true, true, false, 2)?;
    test_single_helper(8, true, true, false, 2)?;
    test_single_helper(9, true, true, false, 2)?;
    test_single_helper(10, true, true, false, 2)?;
    test_single_helper(11, true, true, false, 2)?;
    test_single_helper(12, true, true, false, 2)?;
    test_single_helper(13, true, true, false, 2)?;
    test_single_helper(14, true, true, false, 2)?;
    test_single_helper(15, true, true, false, 2)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k2() -> Result<(), PCSError> {
    test_single_helper(2, false, true, true, 2)?;
    test_single_helper(3, false, true, true, 2)?;
    test_single_helper(4, false, true, true, 2)?;
    test_single_helper(5, false, true, true, 2)?;
    test_single_helper(6, false, true, true, 2)?;
    test_single_helper(7, false, true, true, 2)?;
    test_single_helper(8, false, true, true, 2)?;
    test_single_helper(9, false, true, true, 2)?;
    test_single_helper(10, false, true, true, 2)?;
    test_single_helper(11, false, true, true, 2)?;
    test_single_helper(12, false, true, true, 2)?;
    test_single_helper(13, false, true, true, 2)?;
    test_single_helper(14, false, true, true, 2)?;
    test_single_helper(15, false, true, true, 2)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_zk_k2() -> Result<(), PCSError> {
    test_single_helper(2, true, true, true, 2)?;
    test_single_helper(3, true, true, true, 2)?;
    test_single_helper(4, true, true, true, 2)?;
    test_single_helper(5, true, true, true, 2)?;
    test_single_helper(6, true, true, true, 2)?;
    test_single_helper(7, true, true, true, 2)?;
    test_single_helper(8, true, true, true, 2)?;
    test_single_helper(9, true, true, true, 2)?;
    test_single_helper(10, true, true, true, 2)?;
    test_single_helper(11, true, true, true, 2)?;
    test_single_helper(12, true, true, true, 2)?;
    test_single_helper(13, true, true, true, 2)?;
    test_single_helper(14, true, true, true, 2)?;
    test_single_helper(15, true, true, true, 2)?;
    Ok(())
}

// ---------------- k = 3 ----------------

#[test]
fn test_dense_k3() -> Result<(), PCSError> {
    test_single_helper(3, false, false, false, 3)?;
    test_single_helper(4, false, false, false, 3)?;
    test_single_helper(5, false, false, false, 3)?;
    test_single_helper(6, false, false, false, 3)?;
    test_single_helper(7, false, false, false, 3)?;
    test_single_helper(8, false, false, false, 3)?;
    test_single_helper(9, false, false, false, 3)?;
    test_single_helper(10, false, false, false, 3)?;
    test_single_helper(11, false, false, false, 3)?;
    test_single_helper(12, false, false, false, 3)?;
    test_single_helper(13, false, false, false, 3)?;
    test_single_helper(14, false, false, false, 3)?;
    test_single_helper(15, false, false, false, 3)?;
    Ok(())
}

#[test]
fn test_dense_zk_k3() -> Result<(), PCSError> {
    test_single_helper(3, true, false, false, 3)?;
    test_single_helper(4, true, false, false, 3)?;
    test_single_helper(5, true, false, false, 3)?;
    test_single_helper(6, true, false, false, 3)?;
    test_single_helper(7, true, false, false, 3)?;
    test_single_helper(8, true, false, false, 3)?;
    test_single_helper(9, true, false, false, 3)?;
    test_single_helper(10, true, false, false, 3)?;
    test_single_helper(11, true, false, false, 3)?;
    test_single_helper(12, true, false, false, 3)?;
    test_single_helper(13, true, false, false, 3)?;
    test_single_helper(14, true, false, false, 3)?;
    test_single_helper(15, true, false, false, 3)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k3() -> Result<(), PCSError> {
    test_single_helper(3, false, false, true, 3)?;
    test_single_helper(4, false, false, true, 3)?;
    test_single_helper(5, false, false, true, 3)?;
    test_single_helper(6, false, false, true, 3)?;
    test_single_helper(7, false, false, true, 3)?;
    test_single_helper(8, false, false, true, 3)?;
    test_single_helper(9, false, false, true, 3)?;
    test_single_helper(10, false, false, true, 3)?;
    test_single_helper(11, false, false, true, 3)?;
    test_single_helper(12, false, false, true, 3)?;
    test_single_helper(13, false, false, true, 3)?;
    test_single_helper(14, false, false, true, 3)?;
    test_single_helper(15, false, false, true, 3)?;
    Ok(())
}

#[test]
fn test_dense_boolean_zk_k3() -> Result<(), PCSError> {
    test_single_helper(3, true, false, true, 3)?;
    test_single_helper(4, true, false, true, 3)?;
    test_single_helper(5, true, false, true, 3)?;
    test_single_helper(6, true, false, true, 3)?;
    test_single_helper(7, true, false, true, 3)?;
    test_single_helper(8, true, false, true, 3)?;
    test_single_helper(9, true, false, true, 3)?;
    test_single_helper(10, true, false, true, 3)?;
    test_single_helper(11, true, false, true, 3)?;
    test_single_helper(12, true, false, true, 3)?;
    test_single_helper(13, true, false, true, 3)?;
    test_single_helper(14, true, false, true, 3)?;
    test_single_helper(15, true, false, true, 3)?;
    Ok(())
}

#[test]
fn test_sparse_k3() -> Result<(), PCSError> {
    test_single_helper(3, false, true, false, 3)?;
    test_single_helper(4, false, true, false, 3)?;
    test_single_helper(5, false, true, false, 3)?;
    test_single_helper(6, false, true, false, 3)?;
    test_single_helper(7, false, true, false, 3)?;
    test_single_helper(8, false, true, false, 3)?;
    test_single_helper(9, false, true, false, 3)?;
    test_single_helper(10, false, true, false, 3)?;
    test_single_helper(11, false, true, false, 3)?;
    test_single_helper(12, false, true, false, 3)?;
    test_single_helper(13, false, true, false, 3)?;
    test_single_helper(14, false, true, false, 3)?;
    test_single_helper(15, false, true, false, 3)?;
    Ok(())
}

#[test]
fn test_sparse_zk_k3() -> Result<(), PCSError> {
    test_single_helper(3, true, true, false, 3)?;
    test_single_helper(4, true, true, false, 3)?;
    test_single_helper(5, true, true, false, 3)?;
    test_single_helper(6, true, true, false, 3)?;
    test_single_helper(7, true, true, false, 3)?;
    test_single_helper(8, true, true, false, 3)?;
    test_single_helper(9, true, true, false, 3)?;
    test_single_helper(10, true, true, false, 3)?;
    test_single_helper(11, true, true, false, 3)?;
    test_single_helper(12, true, true, false, 3)?;
    test_single_helper(13, true, true, false, 3)?;
    test_single_helper(14, true, true, false, 3)?;
    test_single_helper(15, true, true, false, 3)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k3() -> Result<(), PCSError> {
    test_single_helper(3, false, true, true, 3)?;
    test_single_helper(4, false, true, true, 3)?;
    test_single_helper(5, false, true, true, 3)?;
    test_single_helper(6, false, true, true, 3)?;
    test_single_helper(7, false, true, true, 3)?;
    test_single_helper(8, false, true, true, 3)?;
    test_single_helper(9, false, true, true, 3)?;
    test_single_helper(10, false, true, true, 3)?;
    test_single_helper(11, false, true, true, 3)?;
    test_single_helper(12, false, true, true, 3)?;
    test_single_helper(13, false, true, true, 3)?;
    test_single_helper(14, false, true, true, 3)?;
    test_single_helper(15, false, true, true, 3)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_zk_k3() -> Result<(), PCSError> {
    test_single_helper(3, true, true, true, 3)?;
    test_single_helper(4, true, true, true, 3)?;
    test_single_helper(5, true, true, true, 3)?;
    test_single_helper(6, true, true, true, 3)?;
    test_single_helper(7, true, true, true, 3)?;
    test_single_helper(8, true, true, true, 3)?;
    test_single_helper(9, true, true, true, 3)?;
    test_single_helper(10, true, true, true, 3)?;
    test_single_helper(11, true, true, true, 3)?;
    test_single_helper(12, true, true, true, 3)?;
    test_single_helper(13, true, true, true, 3)?;
    test_single_helper(14, true, true, true, 3)?;
    test_single_helper(15, true, true, true, 3)?;
    Ok(())
}

// ---------------- k = 4 ----------------

#[test]
fn test_dense_k4() -> Result<(), PCSError> {
    test_single_helper(4, false, false, false, 4)?;
    test_single_helper(5, false, false, false, 4)?;
    test_single_helper(6, false, false, false, 4)?;
    test_single_helper(7, false, false, false, 4)?;
    test_single_helper(8, false, false, false, 4)?;
    test_single_helper(9, false, false, false, 4)?;
    test_single_helper(10, false, false, false, 4)?;
    test_single_helper(11, false, false, false, 4)?;
    test_single_helper(12, false, false, false, 4)?;
    test_single_helper(13, false, false, false, 4)?;
    test_single_helper(14, false, false, false, 4)?;
    test_single_helper(15, false, false, false, 4)?;
    Ok(())
}

#[test]
fn test_dense_zk_k4() -> Result<(), PCSError> {
    test_single_helper(4, true, false, false, 4)?;
    test_single_helper(5, true, false, false, 4)?;
    test_single_helper(6, true, false, false, 4)?;
    test_single_helper(7, true, false, false, 4)?;
    test_single_helper(8, true, false, false, 4)?;
    test_single_helper(9, true, false, false, 4)?;
    test_single_helper(10, true, false, false, 4)?;
    test_single_helper(11, true, false, false, 4)?;
    test_single_helper(12, true, false, false, 4)?;
    test_single_helper(13, true, false, false, 4)?;
    test_single_helper(14, true, false, false, 4)?;
    test_single_helper(15, true, false, false, 4)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k4() -> Result<(), PCSError> {
    test_single_helper(4, false, false, true, 4)?;
    test_single_helper(5, false, false, true, 4)?;
    test_single_helper(6, false, false, true, 4)?;
    test_single_helper(7, false, false, true, 4)?;
    test_single_helper(8, false, false, true, 4)?;
    test_single_helper(9, false, false, true, 4)?;
    test_single_helper(10, false, false, true, 4)?;
    test_single_helper(11, false, false, true, 4)?;
    test_single_helper(12, false, false, true, 4)?;
    test_single_helper(13, false, false, true, 4)?;
    test_single_helper(14, false, false, true, 4)?;
    test_single_helper(15, false, false, true, 4)?;
    Ok(())
}

#[test]
fn test_dense_boolean_zk_k4() -> Result<(), PCSError> {
    test_single_helper(4, true, false, true, 4)?;
    test_single_helper(5, true, false, true, 4)?;
    test_single_helper(6, true, false, true, 4)?;
    test_single_helper(7, true, false, true, 4)?;
    test_single_helper(8, true, false, true, 4)?;
    test_single_helper(9, true, false, true, 4)?;
    test_single_helper(10, true, false, true, 4)?;
    test_single_helper(11, true, false, true, 4)?;
    test_single_helper(12, true, false, true, 4)?;
    test_single_helper(13, true, false, true, 4)?;
    test_single_helper(14, true, false, true, 4)?;
    test_single_helper(15, true, false, true, 4)?;
    Ok(())
}

#[test]
fn test_sparse_k4() -> Result<(), PCSError> {
    test_single_helper(4, false, true, false, 4)?;
    test_single_helper(5, false, true, false, 4)?;
    test_single_helper(6, false, true, false, 4)?;
    test_single_helper(7, false, true, false, 4)?;
    test_single_helper(8, false, true, false, 4)?;
    test_single_helper(9, false, true, false, 4)?;
    test_single_helper(10, false, true, false, 4)?;
    test_single_helper(11, false, true, false, 4)?;
    test_single_helper(12, false, true, false, 4)?;
    test_single_helper(13, false, true, false, 4)?;
    test_single_helper(14, false, true, false, 4)?;
    test_single_helper(15, false, true, false, 4)?;
    Ok(())
}

#[test]
fn test_sparse_zk_k4() -> Result<(), PCSError> {
    test_single_helper(4, true, true, false, 4)?;
    test_single_helper(5, true, true, false, 4)?;
    test_single_helper(6, true, true, false, 4)?;
    test_single_helper(7, true, true, false, 4)?;
    test_single_helper(8, true, true, false, 4)?;
    test_single_helper(9, true, true, false, 4)?;
    test_single_helper(10, true, true, false, 4)?;
    test_single_helper(11, true, true, false, 4)?;
    test_single_helper(12, true, true, false, 4)?;
    test_single_helper(13, true, true, false, 4)?;
    test_single_helper(14, true, true, false, 4)?;
    test_single_helper(15, true, true, false, 4)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k4() -> Result<(), PCSError> {
    test_single_helper(4, false, true, true, 4)?;
    test_single_helper(5, false, true, true, 4)?;
    test_single_helper(6, false, true, true, 4)?;
    test_single_helper(7, false, true, true, 4)?;
    test_single_helper(8, false, true, true, 4)?;
    test_single_helper(9, false, true, true, 4)?;
    test_single_helper(10, false, true, true, 4)?;
    test_single_helper(11, false, true, true, 4)?;
    test_single_helper(12, false, true, true, 4)?;
    test_single_helper(13, false, true, true, 4)?;
    test_single_helper(14, false, true, true, 4)?;
    test_single_helper(15, false, true, true, 4)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_zk_k4() -> Result<(), PCSError> {
    test_single_helper(4, true, true, true, 4)?;
    test_single_helper(5, true, true, true, 4)?;
    test_single_helper(6, true, true, true, 4)?;
    test_single_helper(7, true, true, true, 4)?;
    test_single_helper(8, true, true, true, 4)?;
    test_single_helper(9, true, true, true, 4)?;
    test_single_helper(10, true, true, true, 4)?;
    test_single_helper(11, true, true, true, 4)?;
    test_single_helper(12, true, true, true, 4)?;
    test_single_helper(13, true, true, true, 4)?;
    test_single_helper(14, true, true, true, 4)?;
    test_single_helper(15, true, true, true, 4)?;
    Ok(())
}

// ---------------- k = 5 ----------------

#[test]
fn test_dense_k5() -> Result<(), PCSError> {
    // Keep your original k-argument pattern
    test_single_helper(5, false, false, false, 4)?;
    test_single_helper(6, false, false, false, 4)?;
    test_single_helper(7, false, false, false, 4)?;
    test_single_helper(8, false, false, false, 4)?;
    test_single_helper(9, false, false, false, 5)?;
    test_single_helper(10, false, false, false, 5)?;
    test_single_helper(11, false, false, false, 5)?;
    test_single_helper(12, false, false, false, 5)?;
    test_single_helper(13, false, false, false, 5)?;
    test_single_helper(14, false, false, false, 5)?;
    test_single_helper(15, false, false, false, 5)?;
    Ok(())
}

#[test]
fn test_dense_zk_k5() -> Result<(), PCSError> {
    test_single_helper(5, true, false, false, 4)?;
    test_single_helper(6, true, false, false, 4)?;
    test_single_helper(7, true, false, false, 4)?;
    test_single_helper(8, true, false, false, 4)?;
    test_single_helper(9, true, false, false, 5)?;
    test_single_helper(10, true, false, false, 5)?;
    test_single_helper(11, true, false, false, 5)?;
    test_single_helper(12, true, false, false, 5)?;
    test_single_helper(13, true, false, false, 5)?;
    test_single_helper(14, true, false, false, 5)?;
    test_single_helper(15, true, false, false, 5)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k5() -> Result<(), PCSError> {
    test_single_helper(5, false, false, true, 4)?;
    test_single_helper(6, false, false, true, 4)?;
    test_single_helper(7, false, false, true, 4)?;
    test_single_helper(8, false, false, true, 4)?;
    test_single_helper(9, false, false, true, 5)?;
    test_single_helper(10, false, false, true, 5)?;
    test_single_helper(11, false, false, true, 5)?;
    test_single_helper(12, false, false, true, 5)?;
    test_single_helper(13, false, false, true, 5)?;
    test_single_helper(14, false, false, true, 5)?;
    test_single_helper(15, false, false, true, 5)?;
    Ok(())
}

#[test]
fn test_dense_boolean_zk_k5() -> Result<(), PCSError> {
    test_single_helper(5, true, false, true, 4)?;
    test_single_helper(6, true, false, true, 4)?;
    test_single_helper(7, true, false, true, 4)?;
    test_single_helper(8, true, false, true, 4)?;
    test_single_helper(9, true, false, true, 5)?;
    test_single_helper(10, true, false, true, 5)?;
    test_single_helper(11, true, false, true, 5)?;
    test_single_helper(12, true, false, true, 5)?;
    test_single_helper(13, true, false, true, 5)?;
    test_single_helper(14, true, false, true, 5)?;
    test_single_helper(15, true, false, true, 5)?;
    Ok(())
}

#[test]
fn test_sparse_k5() -> Result<(), PCSError> {
    test_single_helper(5, false, true, false, 4)?;
    test_single_helper(6, false, true, false, 4)?;
    test_single_helper(7, false, true, false, 4)?;
    test_single_helper(8, false, true, false, 4)?;
    test_single_helper(9, false, true, false, 5)?;
    test_single_helper(10, false, true, false, 5)?;
    test_single_helper(11, false, true, false, 5)?;
    test_single_helper(12, false, true, false, 5)?;
    test_single_helper(13, false, true, false, 5)?;
    test_single_helper(14, false, true, false, 5)?;
    test_single_helper(15, false, true, false, 5)?;
    Ok(())
}

#[test]
fn test_sparse_zk_k5() -> Result<(), PCSError> {
    test_single_helper(5, true, true, false, 4)?;
    test_single_helper(6, true, true, false, 4)?;
    test_single_helper(7, true, true, false, 4)?;
    test_single_helper(8, true, true, false, 4)?;
    test_single_helper(9, true, true, false, 5)?;
    test_single_helper(10, true, true, false, 5)?;
    test_single_helper(11, true, true, false, 5)?;
    test_single_helper(12, true, true, false, 5)?;
    test_single_helper(13, true, true, false, 5)?;
    test_single_helper(14, true, true, false, 5)?;
    test_single_helper(15, true, true, false, 5)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k5() -> Result<(), PCSError> {
    test_single_helper(5, false, true, true, 4)?;
    test_single_helper(6, false, true, true, 4)?;
    test_single_helper(7, false, true, true, 4)?;
    test_single_helper(8, false, true, true, 4)?;
    test_single_helper(9, false, true, true, 5)?;
    test_single_helper(10, false, true, true, 5)?;
    test_single_helper(11, false, true, true, 5)?;
    test_single_helper(12, false, true, true, 5)?;
    test_single_helper(13, false, true, true, 5)?;
    test_single_helper(14, false, true, true, 5)?;
    test_single_helper(15, false, true, true, 5)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_zk_k5() -> Result<(), PCSError> {
    test_single_helper(5, true, true, true, 4)?;
    test_single_helper(6, true, true, true, 4)?;
    test_single_helper(7, true, true, true, 4)?;
    test_single_helper(8, true, true, true, 4)?;
    test_single_helper(9, true, true, true, 5)?;
    test_single_helper(10, true, true, true, 5)?;
    test_single_helper(11, true, true, true, 5)?;
    test_single_helper(12, true, true, true, 5)?;
    test_single_helper(13, true, true, true, 5)?;
    test_single_helper(14, true, true, true, 5)?;
    test_single_helper(15, true, true, true, 5)?;
    Ok(())
}
