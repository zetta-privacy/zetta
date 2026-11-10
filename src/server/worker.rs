//! Worker: three phases per tick.
//! Phase 1 `prepare` — catch the local mirror up to the proven on-chain
//!   state, derived exclusively from chain. Knows nothing about later
//!   phases.
//! Phase 2 (next) — apply the interval's new transfers on an isolated copy,
//!   prove + submit updateRoot, discard the copy.

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use folding_schemes::frontend::FCircuit;
use std::time::Duration;
use tracing::{debug, info};
use zkp::poseidon2;

use crate::burn::address_to_fr;
use crate::config::Config;
use crate::server::state::State;
use crate::server::wallet::Wallet;
use crate::server::{BurnStep, IVerifier, SharedState, u256_to_fr};

use ark_bn254::Fr;
use ark_ff::Zero; // replace `use ark_bn254::Fr;` with the line above
use std::time::Instant;

use crate::zkp::TREE_DEPTH;
use crate::zkp::{RootTransitionCircuit, RootTransitionWitness, prove_root_transition};

/// Max blocks per eth_getLogs call — under hosted-RPC range caps.
const LOG_CHUNK: u64 = 200;

/// A single on-chain burn step. `burn_index` is the tree-leaf index assigned
/// during `sync_chain`; it is `0` when read straight off the chain.
#[derive(Clone, Copy, Debug)]
pub struct BurnEvent {
    pub burn_index: u64,
    pub block_number: u64,
    pub log_index: u64,
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: Fr,
    pub hash_chain: Fr,
}

/// Phase-1 output: progress bookkeeping. The mirror state itself is extended
/// in place and read back by later phases from the shared slot.
pub struct Prepared {
    /// transferIndex the mirror caught up to.
    pub proven: u64,
    /// Highest block whose events are now fully in the mirror (cursor target).
    pub last_replayed_block: Option<u64>,
    pub latest_block: u64,
}

pub async fn run(
    state: &SharedState,
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_block = config.last_block;
    loop {
        // Phase 1: catch the mirror up to the finalized prefix [0..transferIndex).
        let mut next = state.lock().unwrap().clone(); // shared slot untouched on failure
        let p = prepare(&mut next, provider, config, last_block).await?;
        if let Some(b) = p.last_replayed_block {
            last_block = b;
        }
        debug!(
            stage = "prepare",
            proven = p.proven,
            block = p.latest_block,
            "caught up"
        );
        *state.lock().unwrap() = next;

        // Phase 2: reserve at the tip, then process the fresh chunk.
        reserve(provider, wallet, config).await?;
        advance_start_hash_chain(provider, wallet, config).await?;
        process_update_root(state, provider, wallet, config, last_block).await?;

        let secs = state.lock().unwrap().poll_interval_secs;
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}

async fn reserve(
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let call = verifier.reserveHashChain();
    let rc = send_and_confirm(wallet, provider, config.verifier, call.calldata().clone()).await?;
    debug!(stage = "reserve", tx = %rc.transaction_hash, "hash chain reserved");
    Ok(())
}

/// Phase 1 — preparation. Extends the mirror with the proven prefix of the
/// fresh window: registrations from the DB; proven root / hash chain /
/// withdraw watermark / reservation from the verifier; events since the last
/// prepared block.
async fn prepare(
    s: &mut State,
    provider: &impl Provider,
    config: &Config,
    from_block: u64,
) -> Result<Prepared, Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);

    // Chain facts, all at the same block: what the contract has already
    // processed + the epoch target pinned by `reserve`.
    let latest = provider.get_block_number().await?;
    let block = alloy::eips::BlockId::number(latest);
    let proven: u64 = verifier
        .transferIndex()
        .block(block)
        .call()
        .await?
        .try_into()?;
    let on_chain_root = u256_to_fr(verifier.transferRoot().block(block).call().await?);
    let on_chain_chain = u256_to_fr(verifier.transferHashChain().block(block).call().await?);

    let events = fetch_chain_events(provider, config.token, from_block, latest).await?;
    let target_block = sync_chain(&mut *s, &events, on_chain_chain, &mut apply_transfer)?;

    if s.chain.index() != proven {
        return Err(format!(
            "chain value reached at index {} but proven is {proven} (chain/root disagreement?)",
            s.chain.index()
        )
        .into());
    }
    if s.tree.root() != on_chain_root {
        return Err(format!(
            "local mirror diverged from contract: root {} vs {on_chain_root}",
            s.tree.root()
        )
        .into());
    }

    Ok(Prepared {
        proven,
        last_replayed_block: target_block,
        latest_block: latest,
    })
}

async fn process_update_root(
    state: &SharedState,
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
    from_block: u64,
) -> Result<Option<State>, Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let mut work = state.lock().unwrap().clone();

    let reserved_index: u64 = verifier.reservedIndex().call().await?.try_into()?;
    let reserved_chain = u256_to_fr(verifier.reservedHashChain().call().await?);
    let proven = work.chain.index();

    if proven >= reserved_index {
        return Ok(None);
    }

    let z_0 = vec![Fr::from(proven), work.chain.state(), work.tree.root()];

    let latest = provider.get_block_number().await?;
    let events = fetch_chain_events(provider, config.token, from_block, latest).await?;

    let mut witnesses = Vec::new();
    sync_chain(&mut work, &events, reserved_chain, &mut |s, e| {
        witnesses.push(commit_transfer(s, e)?);
        Ok(())
    })?;

    if work.chain.index() != reserved_index {
        return Err(format!(
            "reserved chain reached at index {} but reservedIndex is {reserved_index}",
            work.chain.index()
        )
        .into());
    }

    submit_update_root(wallet, provider, config, z_0, witnesses).await?;

    Ok(Some(work))
}

/// Multi-leaf epoch — Nova IVC folded per transfer + Groth16 decider.
async fn submit_update_root(
    wallet: &Wallet,
    provider: &impl Provider,
    config: &Config,
    z_0: Vec<Fr>,
    witnesses: Vec<RootTransitionWitness>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        stage = "commit",
        steps = witnesses.len(),
        "proving root transition (Nova + decider)"
    );
    let t = Instant::now();
    let calldata = prove_root_transition(RootTransitionCircuit::new(())?, z_0, witnesses)?;
    info!(stage = "commit", elapsed = ?t.elapsed(), "root proof done");

    // calldata = [verifyOpaqueNovaProof selector (4B)] + [32 × 32B proof]
    let proof: [U256; 32] = calldata[4..]
        .chunks_exact(32)
        .map(U256::from_be_slice)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|v: Vec<U256>| format!("root proof has {} words, expected 32", v.len()))?;

    let verifier = IVerifier::new(config.verifier, provider);
    let call = verifier.updateRoot(proof);
    let rc = send_and_confirm(wallet, provider, config.verifier, call.calldata().clone()).await?;
    info!(stage = "commit", tx = %rc.transaction_hash, gas = rc.gas_used, "updateRoot confirmed");

    Ok(())
}

/// Apply one transfer to the working copy, recording the root-step witness.
fn commit_transfer(
    s: &mut State,
    e: &BurnEvent,
) -> Result<RootTransitionWitness, Box<dyn std::error::Error>> {
    let mut merkle_path = [Fr::zero(); TREE_DEPTH];
    merkle_path.copy_from_slice(&s.tree.proof_for_empty(s.tree.len()));
    let witness = RootTransitionWitness {
        to: address_to_fr(e.to),
        value: e.value,
        merkle_path,
    };
    Ok(witness)
}

/// Every BurnStep in [from_block, to_block] inclusive, ordered by
/// (block, log index). The carried chain value makes windows self-verifying
/// and exact-cut.
async fn fetch_chain_events(
    provider: &impl Provider,
    token: Address,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<BurnEvent>, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    let mut from = from_block;
    while from <= to_block {
        let to = (from + LOG_CHUNK - 1).min(to_block);
        let filter = Filter::new()
            .address(token)
            .event_signature(BurnStep::SIGNATURE_HASH)
            .from_block(from)
            .to_block(to);
        for log in provider.get_logs(&filter).await? {
            let decoded = log.log_decode::<BurnStep>()?;
            let d = decoded.data();
            events.push(BurnEvent {
                burn_index: 0, // assigned during sync_chain
                block_number: log.block_number.ok_or("log without block number")?,
                log_index: log.log_index.ok_or("log without log index")?,
                from: d.from.into_array(),
                to: d.to.into_array(),
                value: u256_to_fr(d.value),
                hash_chain: u256_to_fr(d.hashChain),
            });
        }
        from = to + 1;
    }
    events.sort_by_key(|e| (e.block_number, e.log_index));
    Ok(events)
}

/// Replay one proven transfer: tree insert + hash-chain step + ledger entries.
fn apply_transfer(s: &mut State, e: &BurnEvent) -> Result<(), Box<dyn std::error::Error>> {
    let leaf_index = s.tree.len() as u64;
    let j = match s.address_counts.get_mut(&e.to) {
        Some(c) => {
            *c += 1;
            *c
        }
        None => {
            s.address_counts.insert(e.to, 1);
            1
        }
    };
    s.cuckoo_entries.push((e.to, j, leaf_index));
    s.values.push(e.value);
    s.tree.insert(poseidon2(address_to_fr(e.to), e.value)?);
    s.chain.apply(e.to, e.value);
    Ok(())
}

/// Advance the mirror along `events` until its hash chain equals `target`.
/// Position is recovered by chain value, so `events` may overlap history.
/// Returns the block of the target-carrying event, or None if already at target.
fn sync_chain(
    s: &mut State,
    events: &[BurnEvent],
    target: Fr,
    apply: &mut impl FnMut(&mut State, &BurnEvent) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    if s.chain.state() == target {
        return Ok(None); // already at the frontier
    }

    let mut it = events.iter().copied();
    let start = s.chain.state();

    if !start.is_zero() {
        match it.find(|e| e.hash_chain == start) {
            Some(_) => {}
            None => return Err("sync point not in window: stale cursor or reorg".into()),
        }
    }

    for mut ev in it {
        ev.burn_index = s.tree.len() as u64;
        apply(s, &ev)?;
        if s.chain.state() != ev.hash_chain {
            return Err(format!(
                "chain mismatch at block {}: mirror out of sync (gap or reorg)",
                ev.block_number
            )
            .into());
        }
        if ev.hash_chain == target {
            return Ok(Some(ev.block_number));
        }
    }

    Err(format!("target chain value {target} not in window").into())
}

pub async fn send_and_confirm(
    wallet: &Wallet,
    provider: &impl Provider,
    to: Address,
    data: alloy::primitives::Bytes,
) -> Result<alloy::rpc::types::TransactionReceipt, Box<dyn std::error::Error>> {
    let hash = wallet.send_tx(to, data, None).await?;
    for _ in 0..180 {
        if let Some(rc) = provider.get_transaction_receipt(hash).await? {
            return Ok(rc);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("tx {hash} not mined after 180s").into())
}

async fn advance_start_hash_chain(
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let reserved: u64 = verifier.reservedIndex().call().await?.try_into()?;
    let transfer: u64 = verifier.transferIndex().call().await?.try_into()?;
    if reserved.saturating_sub(transfer) < 2 {
        debug!(
            stage = "advance_start",
            reserved, transfer, "headroom < 2 — skip"
        );
        return Ok(());
    }
    let call = verifier.updateStartHashChain();
    let rc = send_and_confirm(wallet, provider, config.verifier, call.calldata().clone()).await?;
    debug!(stage = "advance_start", tx = %rc.transaction_hash, "start hash chain advanced");
    Ok(())
}
