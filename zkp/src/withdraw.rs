use std::borrow::Borrow;

use crate::{TREE_DEPTH, poseidon3_var};
use crate::{merkle_root_var, poseidon2_var};
use ark_bn254::{Fq, Fr};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_grumpkin::Projective as G2;
use ark_grumpkin::constraints::GVar;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    groups::CurveVar,
    prelude::{Boolean, ToBitsGadget},
};

use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use folding_schemes::{Error, frontend::FCircuit};

#[derive(Clone, Debug)]
pub struct WithdrawWitness {
    pub pubkey: G2, // P = x·G
    pub sig_r: G2,  // R = k·G
    pub sig_z: Fq,  // z = k + e·x  (grumpkin scalar == bn254 Fq, NOT Fr)
    pub salt: Fr,   // burn address nonce: burn = poseidon3(recipient, P.x, salt)
    pub value: Fr,
    pub index: Fr,
    pub merkle_path: [Fr; TREE_DEPTH],
}

impl Default for WithdrawWitness {
    fn default() -> Self {
        Self {
            pubkey: G2::zero(),
            sig_r: G2::zero(),
            sig_z: Fq::zero(),
            salt: Fr::zero(),
            value: Fr::zero(),
            index: Fr::zero(),
            merkle_path: [Fr::zero(); TREE_DEPTH],
        }
    }
}

#[derive(Clone, Debug)]
pub struct WithdrawWitnessVar {
    pub pubkey: GVar,
    pub sig_r: GVar,
    pub sig_z_bits: Vec<Boolean<Fr>>,
    pub salt: FpVar<Fr>,
    pub value: FpVar<Fr>,
    pub index: FpVar<Fr>,
    pub merkle_path: [FpVar<Fr>; TREE_DEPTH],
}

impl AllocVar<WithdrawWitness, Fr> for WithdrawWitnessVar {
    fn new_variable<T: Borrow<WithdrawWitness>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let w = f()?;
        let w = w.borrow();

        let pubkey = GVar::new_variable(cs.clone(), || Ok(w.pubkey), mode)?;
        let sig_r = GVar::new_variable(cs.clone(), || Ok(w.sig_r), mode)?;

        // decompose z (Fq) to bits OUTSIDE the circuit — no in-circuit cost.
        let z_bits = w.sig_z.into_bigint().to_bits_le();
        let mut sig_z_bits = Vec::with_capacity(z_bits.len());
        for bit in z_bits {
            sig_z_bits.push(Boolean::<Fr>::new_witness(cs.clone(), || Ok(bit))?);
        }

        Ok(Self {
            pubkey,
            sig_r,
            sig_z_bits,
            salt: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.salt), mode)?,
            value: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.value), mode)?,
            index: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.index), mode)?,
            merkle_path: <[FpVar<Fr>; TREE_DEPTH] as AllocVar<[Fr; TREE_DEPTH], Fr>>::new_variable(
                cs.clone(),
                || Ok(w.merkle_path),
                mode,
            )?,
        })
    }
}

/// e = poseidon3(R.x, pk.x, recipient) over Fr.
fn challenge(pk: &GVar, r: &GVar, recipient: FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let r_aff = r.to_affine()?;
    let pk_aff = pk.to_affine()?;
    poseidon3_var(r_aff.x, pk_aff.x, recipient)
}

/// require z·G − e·P == R
pub fn schnorr_verify(
    pk: &GVar,
    r: &GVar,
    z_bits: &[Boolean<Fr>],
    recipient: FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let e = challenge(pk, r, recipient)?;
    let e_bits = e.to_bits_le()?;

    let g = GVar::constant(G2::generator());
    let zg = g.scalar_mul_le(z_bits.iter())?;
    let epk = pk.scalar_mul_le(e_bits.iter())?;
    (zg - epk).enforce_equal(r)?;
    Ok(())
}

/// Withdraw step circuit: one step per receipt.
/// State z = [indexWithOffset, totalValue, transferRoot, recipient].
#[derive(Clone, Debug)]
pub struct WithdrawCircuit;

impl FCircuit<Fr> for WithdrawCircuit {
    type Params = ();
    type ExternalInputs = WithdrawWitness;
    type ExternalInputsVar = WithdrawWitnessVar;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self)
    }

    fn state_len(&self) -> usize {
        4
    }

    fn generate_step_constraints(
        &self,
        _: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let index_with_offset = z_i[0].clone();
        let total_value = z_i[1].clone();
        let transfer_root = z_i[2].clone();
        let recipient = z_i[3].clone();

        let pubkey = &external_inputs.pubkey;
        let sig_r = &external_inputs.sig_r;
        let sig_z_bits = &external_inputs.sig_z_bits;
        let salt = external_inputs.salt;
        let value = external_inputs.value;
        let index = external_inputs.index; // GLOBAL burn index
        let merkle_path = &external_inputs.merkle_path;

        // address = low160(poseidon3(recipient, x(P), salt))
        let pk_aff = pubkey.to_affine()?;
        let burn = poseidon3_var(recipient.clone(), pk_aff.x, salt)?;
        let burn_bits = burn.to_bits_le()?;
        let address = Boolean::le_bits_to_fp(&burn_bits[0..160])?;

        // Schnorr verify (proves the user authorized this address)
        schnorr_verify(pubkey, sig_r, sig_z_bits, recipient.clone())?;

        // leaf = poseidon2(address, value)
        let leaf = poseidon2_var(address, value.clone())?;

        // transferRoot == merkle_root(localIndex, leaf, merkle_path)
        let (index_bits, _) = index.to_bits_le_with_top_bits_zero(40)?;
        let local_index = Boolean::le_bits_to_fp(&index_bits[..TREE_DEPTH])?;
        let root = merkle_root_var(local_index, leaf, merkle_path)?;
        root.enforce_equal(&transfer_root)?;

        // index + 1 > indexWithOffset (both are GLOBAL indexes)
        let diff = index.clone() - index_with_offset.clone();
        let _ = diff.to_bits_le_with_top_bits_zero(40)?;

        // value < 2^248
        let _ = value.to_bits_le_with_top_bits_zero(248)?;

        // recipient < 2^246
        let _ = recipient.to_bits_le_with_top_bits_zero(246)?;

        let index_with_offset_next = index + FpVar::<Fr>::one();
        let total_value_next = total_value + value;

        Ok(vec![
            index_with_offset_next,
            total_value_next,
            transfer_root,
            recipient,
        ])
    }
}
