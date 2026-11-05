use ::zkp::{
    RootTransitionCircuit, RootTransitionWitness, prove_root_transition,
    render_root_transition_verifier,
};
use ark_bn254::Fr;
use ark_ff::One;
use ark_ff::Zero;
use ark_r1cs_std::GR1CSVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use folding_schemes::frontend::FCircuit;
use zkp::{
    RootTransitionWitnessVar, cached_root_params, hash_chain_step_var, merkle_root_var, poseidon2,
};

use crate::zkp::TREE_DEPTH;

#[test]
fn root_transition_full_pipeline() -> Result<(), Box<dyn std::error::Error>> {
    use crate::burn::address_to_fr;
    use crate::tree::MerkleTree;
    use solidity_verifiers::evm::{Evm, compile_solidity};

    let transfers = [([0x01u8; 20], 100u64), ([0x02u8; 20], 200u64)];

    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut witnesses = Vec::new();
    for (i, (to, val)) in transfers.iter().enumerate() {
        let proof = tree.proof_for_empty(i);
        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&proof);
        witnesses.push(RootTransitionWitness {
            to: address_to_fr(*to),
            value: Fr::from(*val),
            merkle_path,
        });
        let leaf = poseidon2(address_to_fr(*to), Fr::from(*val)).unwrap();
        tree.insert(leaf);
    }

    let initial_root = MerkleTree::new(TREE_DEPTH).root();
    let z_0 = vec![Fr::zero(), Fr::zero(), initial_root];

    let circuit = RootTransitionCircuit::new(()).unwrap();
    let calldata = prove_root_transition(circuit, z_0, witnesses)?;
    let solidity_code = render_root_transition_verifier(&cached_root_params()?.decider_vp)?;

    let bytecode = compile_solidity(&solidity_code, "NovaDecider");
    let mut evm = Evm::default();
    let verifier_address = evm.create(bytecode);
    let (_, output) = evm.call(verifier_address, calldata);
    assert_eq!(*output.last().unwrap(), 1);

    Ok(())
}

#[test]
fn hash_chain_step_var_matches_native() {
    use crate::burn::address_to_fr;
    use crate::tree::hash_chain_step;
    use ark_relations::gr1cs::ConstraintSystem;

    let cs = ConstraintSystem::<Fr>::new_ref();
    let prev = Fr::from(12345u64);
    let to = [0x11u8; 20];
    let value = Fr::from(100u64);

    let prev_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(prev)).unwrap();
    let to_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(address_to_fr(to))).unwrap();
    let value_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(value)).unwrap();

    let h_var = hash_chain_step_var(prev_var, to_var, value_var).unwrap();
    let h_native = hash_chain_step(prev, to, value);
    assert_eq!(h_var.value().unwrap(), h_native);
}

#[test]
fn merkle_root_var_matches_native() {
    use crate::tree::MerkleTree;
    use ark_relations::gr1cs::ConstraintSystem;

    let mut tree = MerkleTree::new(TREE_DEPTH);
    let leaves: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64 + 1)).collect();
    for &l in &leaves {
        tree.insert(l);
    }
    let root = tree.root();

    let cs = ConstraintSystem::<Fr>::new_ref();
    for (i, &leaf) in leaves.iter().enumerate() {
        let proof = tree.proof(i);
        let index_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(Fr::from(i as u64))).unwrap();
        let leaf_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let siblings_var: Vec<FpVar<Fr>> = proof
            .iter()
            .map(|s| FpVar::<Fr>::new_witness(cs.clone(), || Ok(*s)).unwrap())
            .collect();
        let root_var = merkle_root_var(index_var, leaf_var, &siblings_var).unwrap();
        assert_eq!(root_var.value().unwrap(), root);
    }
}

fn compute_root(leaf: Fr, index: usize, siblings: &[Fr]) -> Fr {
    let mut h = leaf;
    let mut idx = index;
    for &sibling in siblings {
        h = if idx & 1 == 0 {
            poseidon2(h, sibling).unwrap()
        } else {
            poseidon2(sibling, h).unwrap()
        };
        idx >>= 1;
    }
    h
}

#[test]
fn root_transition_circuit_matches_native() {
    use crate::burn::address_to_fr;
    use crate::tree::{MerkleTree, hash_chain_step};
    use ark_relations::gr1cs::ConstraintSystem;

    let transfers = [
        ([0x01u8; 20], 100u64),
        ([0x02u8; 20], 200u64),
        ([0x03u8; 20], 300u64),
    ];

    let mut tree = MerkleTree::new(TREE_DEPTH);
    let mut leaves = Vec::new();
    for (to, val) in transfers {
        let leaf = poseidon2(address_to_fr(to), Fr::from(val)).unwrap();
        leaves.push(leaf);
        tree.insert(leaf);
    }

    let initial_root = MerkleTree::new(TREE_DEPTH).root();
    let mut index = Fr::zero();
    let mut hash_chain = Fr::zero();
    let mut transfer_root = initial_root;

    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = RootTransitionCircuit::new(()).unwrap();

    for (i, (to, val)) in transfers.iter().enumerate() {
        let proof = tree.proof(i);
        let leaf = leaves[i];

        let mut merkle_path = [Fr::zero(); TREE_DEPTH];
        merkle_path.copy_from_slice(&proof);
        let witness = RootTransitionWitness {
            to: address_to_fr(*to),
            value: Fr::from(*val),
            merkle_path,
        };

        let index_next = index + Fr::one();
        let hash_chain_next = hash_chain_step(hash_chain, *to, Fr::from(*val));
        let new_root = compute_root(leaf, i, &proof);

        let z_i = vec![index, hash_chain, transfer_root];
        let z_i_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(z_i.clone())).unwrap();
        let witness_var =
            RootTransitionWitnessVar::new_witness(cs.clone(), || Ok(witness)).unwrap();
        let z_next_var = circuit
            .generate_step_constraints(cs.clone(), i, z_i_var, witness_var)
            .unwrap();

        assert_eq!(z_next_var[0].value().unwrap(), index_next);
        assert_eq!(z_next_var[1].value().unwrap(), hash_chain_next);
        assert_eq!(z_next_var[2].value().unwrap(), new_root);

        index = index_next;
        hash_chain = hash_chain_next;
        transfer_root = new_root;
    }
}
