use crate::config::Settings;
use crate::tree::{HashChain, MerkleTree};
use crate::zkp::TREE_DEPTH;

#[derive(Clone)]
pub struct State {
    /// Single depth-32 ever-growing tree.
    pub tree: MerkleTree,
    pub chain: HashChain,
    pub chain_id: u64,
    pub poll_interval_secs: u64,
    pub rotate_threshold: u64,
}

impl State {
    pub fn new(chain_id: u64, settings: &Settings) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            tree: MerkleTree::new(TREE_DEPTH),
            chain: HashChain::new(),
            chain_id,
            poll_interval_secs: settings.poll_interval_secs,
            rotate_threshold: settings.rotate_threshold,
        })
    }
}
