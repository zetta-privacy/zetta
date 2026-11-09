//! Poseidon Merkle tree + on-chain hash-chain mirror (Phase B).

// src/tree.rs
use crate::zkp::{poseidon2, poseidon3};
use ark_bn254::Fr;
use ark_ff::Zero;

/// Append-only Poseidon Merkle tree: every level keeps its full history.
/// levels[h][k] = value of node (k >> h) at level h, after leaf k.
#[derive(Clone)]
pub struct MerkleTree {
    depth: usize,
    levels: Vec<Vec<Fr>>, // append-only; one entry per leaf per level
    zero_hashes: Vec<Fr>,
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

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// Current root = the latest entry at the top level (or the empty-tree zero hash).
    pub fn root(&self) -> Fr {
        self.levels[self.depth]
            .last()
            .copied()
            .unwrap_or(self.zero_hashes[self.depth])
    }

    /// Insert a leaf; returns path[h] = value of node (leaf_index >> h) after insert.
    pub fn insert_with_path(&mut self, leaf: Fr) -> Vec<Fr> {
        assert!(self.len() < 1 << self.depth, "tree full");
        let leaf_index = self.len();
        self.levels[0].push(leaf);
        let mut path = vec![leaf];
        let mut current = leaf;
        let mut idx = leaf_index;
        for h in 0..self.depth {
            let parent = if idx & 1 == 0 {
                poseidon2(current, self.zero_hashes[h]).expect("poseidon")
            } else {
                // left sibling node (idx-1) at level h; its current value was last
                // written at leaf idx*2^h - 1 (the last leaf in its subtree)
                let left = self.levels[h][idx * (1 << h) - 1];
                poseidon2(left, current).expect("poseidon")
            };
            self.levels[h + 1].push(parent); // append, never overwrite
            current = parent;
            idx >>= 1;
            path.push(current);
        }
        path
    }

    pub fn insert(&mut self, leaf: Fr) -> Fr {
        *self.insert_with_path(leaf).last().unwrap()
    }

    /// Sibling path for leaf `index` (or the empty frontier when index == len),
    /// relative to the current root. length == depth.
    pub fn proof(&self, index: usize) -> Vec<Fr> {
        assert!(index <= self.len(), "index out of range");
        let n = self.len();
        (0..self.depth)
            .map(|h| {
                let x = (index >> (h + 1)) ^ 1;
                let start = x * (1 << h);
                if start < n {
                    let l_max = ((x + 1) * (1 << h) - 1).min(n - 1);
                    self.levels[h][l_max]
                } else {
                    self.zero_hashes[h]
                }
            })
            .collect()
    }

    pub fn proof_for_empty(&self, index: usize) -> Vec<Fr> {
        assert_eq!(index, self.len(), "index must be the next empty slot");
        self.proof(index)
    }

    /// Level h's append-only history: level[h][k] = node (k >> h) value after leaf k.
    pub fn level(&self, h: usize) -> &[Fr] {
        &self.levels[h]
    }
}

/// hash-chain step unchanged
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
