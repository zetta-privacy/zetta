use std::collections::HashMap;

use alloy::primitives::U256;
use ark_bn254::{Fq, Fr};
use ark_grumpkin::Projective as G2;

use crate::config::Settings;
use crate::tree::{HashChain, MerkleTree};
use crate::zkp::TREE_DEPTH;

#[derive(Clone)]
pub struct State {
    /// Single depth-32 ever-growing tree.
    pub tree: MerkleTree,
    pub chain: HashChain,
    pub chain_id: u64,
    pub exchange_addr: [u8; 20],
    pub tweak: [u8; 32],
    /// Registered burn-address pubkeys (P = x·G).
    pub pubkey_by_addr: HashMap<[u8; 20], G2>,
    pub recipient_by_addr: HashMap<[u8; 20], Fr>,
    /// Schnorr authorization per burn address: (R, z).
    pub sig_by_addr: HashMap<[u8; 20], (G2, Fq)>,
    /// Burn-address derivation salt: burn = poseidon3(recipient, P.x, salt).
    pub salt_by_addr: HashMap<[u8; 20], Fr>,
    /// All deposits per burn address: (value, tree_index) per deposit.
    pub deposits: HashMap<[u8; 20], Vec<([u8; 20], Fr, usize)>>,
    /// Lifetime deposited value per address. Chain-derived; never trimmed.
    pub credits: HashMap<[u8; 20], U256>,
    /// Registration boundary per burn address: deposits at tree index >= this
    /// are claimable; earlier transfers to the address are treated as burned.
    pub registered_from: HashMap<[u8; 20], u64>,
    // User limits.
    pub max_users: i64,
    pub max_cards_per_user: i64,
    pub card_limit_window_days: i64,
    // State struct, after card_limit_window_days:
    pub poll_interval_secs: u64,
    pub rotate_threshold: u64,
}

impl State {
    pub fn new(
        chain_id: u64,
        exchange_addr: [u8; 20],
        tweak: [u8; 32],
        settings: &Settings,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            tree: MerkleTree::new(TREE_DEPTH),
            chain: HashChain::new(),
            chain_id,
            exchange_addr,
            tweak,
            pubkey_by_addr: HashMap::new(),
            recipient_by_addr: HashMap::new(),
            sig_by_addr: HashMap::new(),
            salt_by_addr: HashMap::new(),
            deposits: HashMap::new(),
            credits: HashMap::new(),
            registered_from: HashMap::new(),
            max_users: settings.max_users,
            max_cards_per_user: settings.max_cards_per_user,
            card_limit_window_days: settings.card_limit_window_days,
            poll_interval_secs: settings.poll_interval_secs,
            rotate_threshold: settings.rotate_threshold,
        })
    }

    /// Hot-apply DB-backed settings; reloaded by the worker each tick.
    pub fn apply_settings(&mut self, s: &Settings) {
        self.rotate_threshold = s.rotate_threshold;
        self.max_users = s.max_users;
        self.max_cards_per_user = s.max_cards_per_user;
        self.card_limit_window_days = s.card_limit_window_days;
        self.poll_interval_secs = s.poll_interval_secs;
    }
}
