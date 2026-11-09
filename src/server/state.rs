use std::collections::HashMap;

use crate::config::Settings;
use crate::tree::{HashChain, MerkleTree};
use crate::zkp::TREE_DEPTH;

#[derive(Clone)]
pub struct State {
    /// Single depth-32 ever-growing tree.
    pub tree: MerkleTree,
    pub chain: HashChain,
    pub address_counts: HashMap<[u8; 20], u32>,
    pub cuckoo_entries: Vec<([u8; 20], u32, u64)>,
    pub chain_id: u64,
    pub poll_interval_secs: u64,
    pub rotate_threshold: u64,
}

impl State {
    pub fn new(chain_id: u64, settings: &Settings) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            tree: MerkleTree::new(TREE_DEPTH),
            chain: HashChain::new(),
            address_counts: HashMap::new(),
            cuckoo_entries: Vec::new(),
            chain_id,
            poll_interval_secs: settings.poll_interval_secs,
            rotate_threshold: settings.rotate_threshold,
        })
    }
}
