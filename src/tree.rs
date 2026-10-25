//! Poseidon Merkle tree + on-chain hash-chain mirror (Phase B).

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::zkp::{poseidon2, poseidon3};

/// Append-only Poseidon binary Merkle tree with all levels materialized.
/// levels[0] = leaves … levels[depth] = [root]. Proof queries are O(depth),
/// at the cost of 2^(depth+1)-1 stored nodes when full.
#[derive(Clone)]
pub struct MerkleTree {
    depth: usize,
    levels: Vec<Vec<Fr>>, // levels[h].len() == ceil(leaves / 2^h)
    zero_hashes: Vec<Fr>, // zero_hashes[h] = empty subtree of height h
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut zero_hashes = Vec::with_capacity(depth + 1);
        let mut z = poseidon2(Fr::zero(), Fr::zero()).expect("poseidon");
        zero_hashes.push(z);
        for _ in 0..depth {
            z = poseidon2(z, z).expect("poseidon");
            zero_hashes.push(z);
        }
        Self {
            depth,
            levels: vec![Vec::new(); depth + 1],
            zero_hashes,
        }
    }

    pub fn root(&self) -> Fr {
        match self.levels[self.depth].first() {
            Some(&r) => r,
            None => self.zero_hashes[self.depth],
        }
    }

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// Append a leaf; returns the new root. O(depth) hashes; every level is
    /// updated in place so proofs never recompute the tree.
    // src/tree.rs — MerkleTree::insert
    pub fn insert(&mut self, leaf: Fr) -> Fr {
        assert!(self.len() < 1 << self.depth, "tree full");
        let mut idx = self.len();
        self.levels[0].push(leaf);
        let mut current = leaf;

        for h in 0..self.depth {
            let parent = if idx & 1 == 0 {
                // Left child: right sibling is the (conceptually empty) zero subtree.
                poseidon2(current, self.zero_hashes[h]).expect("poseidon")
            } else {
                poseidon2(self.levels[h][idx - 1], current).expect("poseidon")
            };
            let parent_idx = idx >> 1;
            if parent_idx < self.levels[h + 1].len() {
                self.levels[h + 1][parent_idx] = parent; // node exists: update in place
            } else {
                self.levels[h + 1].push(parent); // first node at this slot: create
            }
            current = parent;
            idx >>= 1;
        }
        current
    }

    /// Siblings from leaf level up to root (length == depth).
    pub fn proof(&self, index: usize) -> Vec<Fr> {
        assert!(index < self.len(), "index out of range");
        self.path(index)
    }

    /// Siblings for the (empty) leaf at `index`, where `index == self.len()`.
    pub fn proof_for_empty(&self, index: usize) -> Vec<Fr> {
        assert_eq!(index, self.len(), "index must be the next empty slot");
        self.path(index)
    }

    fn path(&self, index: usize) -> Vec<Fr> {
        let mut proof = Vec::with_capacity(self.depth);
        let mut idx = index;
        for h in 0..self.depth {
            let sib = idx ^ 1;
            proof.push(if sib < self.levels[h].len() {
                self.levels[h][sib]
            } else {
                self.zero_hashes[h]
            });
            idx >>= 1;
        }
        proof
    }
}

/// One hash-chain step: `poseidon3(prev, address_to_fr(to), value)`.
pub fn hash_chain_step(prev: Fr, to: [u8; 20], value: Fr) -> Fr {
    poseidon3(prev, crate::burn::address_to_fr(to), value).expect("poseidon")
}

/// Off-chain mirror of the on-chain `burnHashChain`.
#[derive(Default, Clone)]
pub struct HashChain {
    state: Fr,
    index: u64,
}

impl HashChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> Fr {
        self.state
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    /// Apply one transfer; returns the new state.
    pub fn apply(&mut self, to: [u8; 20], value: Fr) -> Fr {
        self.state = hash_chain_step(self.state, to, value);
        self.index += 1;
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::TREE_DEPTH;

    /// Verify a Merkle proof for `leaf` at `index` against `root`.
    pub fn verify_proof(leaf: Fr, index: usize, proof: &[Fr], root: Fr) -> bool {
        let mut h = leaf;
        let mut idx = index;
        for &sibling in proof {
            h = if idx & 1 == 0 {
                poseidon2(h, sibling).expect("poseidon")
            } else {
                poseidon2(sibling, h).expect("poseidon")
            };
            idx >>= 1;
        }
        h == root
    }

    #[test]
    fn empty_tree_root_is_zero_hash() {
        let tree = MerkleTree::new(TREE_DEPTH);
        let mut z = poseidon2(Fr::zero(), Fr::zero()).unwrap();
        for _ in 0..32 {
            z = poseidon2(z, z).unwrap();
        }
        assert_eq!(tree.root(), z);
    }

    #[test]
    fn insert_and_verify_proofs() {
        let mut tree = MerkleTree::new(TREE_DEPTH);
        let leaves: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64 + 1)).collect();
        for &l in &leaves {
            tree.insert(l);
        }
        let root = tree.root();
        for (i, &l) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert_eq!(proof.len(), 32);
            assert!(verify_proof(l, i, &proof, root));
        }
        // tampered leaf fails
        assert!(!verify_proof(Fr::from(999u64), 0, &tree.proof(0), root));
    }

    #[test]
    fn hash_chain_deterministic_and_in_range() {
        let mut chain = HashChain::new();
        let s0 = chain.apply([0x11u8; 20], Fr::from(100u64));
        let s1 = chain.apply([0x22u8; 20], Fr::from(200u64));
        assert_eq!(chain.index(), 2);
        // deterministic
        let mut chain2 = HashChain::new();
        chain2.apply([0x11u8; 20], Fr::from(100u64));
        chain2.apply([0x22u8; 20], Fr::from(200u64));
        assert_eq!(chain2.state(), chain.state());
        // different input -> different state
        assert_ne!(s0, s1);
    }

    #[test]
    fn print_constants() {
        let tree = MerkleTree::new(TREE_DEPTH);
        println!("INITIAL_ROOT = {}", tree.root());
        let hc = hash_chain_step(Fr::zero(), [0x01u8; 20], Fr::from(100u64));
        println!("CANONICAL_HASH_CHAIN = {}", hc);
    }
}
