use std::{borrow::Borrow, marker::PhantomData};

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use folding_schemes::{Error, frontend::FCircuit};

use crate::{TREE_DEPTH, poseidon2_var};

pub fn hash_chain_step_var(
    prev: FpVar<Fr>,
    to: FpVar<Fr>,
    value: FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    crate::poseidon3_var(prev, to, value)
}

/// In-circuit Merkle root: hash `leaf` up `siblings` (depth 32), using `index` bits.
pub fn merkle_root_var(
    index: FpVar<Fr>,
    leaf: FpVar<Fr>,
    siblings: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let (index_bits, _) = index.to_bits_le_with_top_bits_zero(siblings.len())?;
    let mut h = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        let bit = &index_bits[level];
        // bit=0 -> left: poseidon2(h, sibling); bit=1 -> right: poseidon2(sibling, h)
        let a = bit.select(sibling, &h)?;
        let b = bit.select(&h, sibling)?;
        h = poseidon2_var(a, b)?;
    }
    Ok(h)
}

#[derive(Clone, Debug)]
pub struct RootTransitionWitness {
    pub to: Fr,
    pub value: Fr,
    pub merkle_path: [Fr; TREE_DEPTH],
}

impl Default for RootTransitionWitness {
    fn default() -> Self {
        Self {
            to: Fr::zero(),
            value: Fr::zero(),
            merkle_path: [Fr::zero(); TREE_DEPTH],
        }
    }
}

#[derive(Clone, Debug)]
pub struct RootTransitionWitnessVar {
    pub to: FpVar<Fr>,
    pub value: FpVar<Fr>,
    pub merkle_path: [FpVar<Fr>; TREE_DEPTH],
}

impl AllocVar<RootTransitionWitness, Fr> for RootTransitionWitnessVar {
    fn new_variable<T: Borrow<RootTransitionWitness>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let w = f()?;
        let w = w.borrow();
        Ok(Self {
            to: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.to), mode)?,
            value: FpVar::<Fr>::new_variable(cs.clone(), || Ok(w.value), mode)?,
            merkle_path: <[FpVar<Fr>; TREE_DEPTH] as AllocVar<[Fr; TREE_DEPTH], Fr>>::new_variable(
                cs.clone(),
                || Ok(w.merkle_path),
                mode,
            )?,
        })
    }
}

/// Root-transition step circuit: one step per transfer.
/// State z_i = [index, hashChain, transferRoot].
/// Witness per step = [to, value, merkle_path[0..32]].
#[derive(Clone, Copy, Debug)]
pub struct RootTransitionCircuit {
    _f: PhantomData<Fr>,
}

impl FCircuit<Fr> for RootTransitionCircuit {
    type Params = ();
    type ExternalInputs = RootTransitionWitness;
    type ExternalInputsVar = RootTransitionWitnessVar;

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        _: ConstraintSystemRef<Fr>,
        _i: usize,
        z_i: Vec<FpVar<Fr>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let index = z_i[0].clone();
        let hash_chain = z_i[1].clone();
        let transfer_root = z_i[2].clone();

        let to = external_inputs.to;
        let value = external_inputs.value;
        let merkle_path = &external_inputs.merkle_path;

        // index' = index + 1
        let index_next = index.clone() + FpVar::<Fr>::one();

        // hashChain' = hash_chain_step(hashChain, to, value)
        let hash_chain_next = hash_chain_step_var(hash_chain, to.clone(), value.clone())?;

        // empty leaf = poseidon2(0, 0)
        let empty_leaf = poseidon2_var(FpVar::<Fr>::zero(), FpVar::<Fr>::zero())?;

        // old root = merkle_root(index, empty_leaf, merkle_path); enforce == transfer_root
        let old_root = merkle_root_var(index.clone(), empty_leaf, merkle_path)?;
        old_root.enforce_equal(&transfer_root)?;

        // new leaf = poseidon2(to, value)
        let new_leaf = poseidon2_var(to, value)?;

        // new root = merkle_root(index, new_leaf, merkle_path)
        let new_root = merkle_root_var(index, new_leaf, merkle_path)?;

        Ok(vec![index_next, hash_chain_next, new_root])
    }
}
