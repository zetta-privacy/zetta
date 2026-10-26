use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_ff::PrimeField;
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use folding_schemes::{
    FoldingScheme,
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::{
        nova::{Nova, PreprocessorParam, decider_eth::DeciderEthCircuit},
        traits::Dummy,
    },
    frontend::{FCircuit, utils::CustomFCircuit},
    transcript::poseidon::poseidon_canonical_config,
};

/// Tiny standalone circuit (4 constraints): `y == x^3 + x + 5`.
/// Use this to debug the phase-2 MPC quickly.
#[derive(Clone, Debug, Default)]
pub struct CubicCircuit<F: PrimeField> {
    pub x: Option<F>,
    pub y: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for CubicCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x = FpVar::<F>::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let y = FpVar::<F>::new_input(cs, || self.y.ok_or(SynthesisError::AssignmentMissing))?;
        let x2 = &x * &x;
        let rhs = &x2 * &x + &x + FpVar::<F>::constant(F::from(5u64));
        y.enforce_equal(&rhs)?;
        Ok(())
    }
}

/// Build a Nova decider circuit over a trivial step circuit, so the decider
/// ceremony path is debuggable without paying the root/withdraw circuit cost.
pub fn test_decider_circuit() -> Result<DeciderEthCircuit<G1, G2>, Box<dyn std::error::Error>> {
    type TestN = Nova<G1, G2, CustomFCircuit<Fr>, KZG<'static, Bn254>, Pedersen<G2>, false>;

    let f_circuit = CustomFCircuit::<Fr>::new(10)?; // 10 constraints
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut rng = ark_std::rand::rngs::OsRng;
    let prep = PreprocessorParam::new(poseidon_config, f_circuit.clone());
    let (nova_pp, nova_vp) =
        <TestN as FoldingScheme<G1, G2, CustomFCircuit<Fr>>>::preprocess(&mut rng, &prep)?;

    Ok(DeciderEthCircuit::<G1, G2>::dummy((
        nova_vp.r1cs,
        nova_vp.cf_r1cs,
        nova_pp.cf_cs_pp,
        nova_pp.poseidon_config,
        (),
        (),
        1,
        2,
    )))
}
