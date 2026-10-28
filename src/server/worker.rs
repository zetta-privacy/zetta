//! Worker: three phases per tick.
//! Phase 1 `prepare` — catch the local mirror up to the proven on-chain
//!   state, derived exclusively from chain + DB. Knows nothing about later
//!   phases.
//! Phase 2 (next) — apply the interval's new transfers on an isolated copy,
//!   prove + submit updateRoot and withdraws, discard the copy.
//! Phase 3 (after) — user payouts, fully independent of 1–2.

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use ark_grumpkin::{Affine as G2Affine, Projective as G2};
use folding_schemes::frontend::FCircuit;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::burn::{address_to_fr, fr_to_bytes32, recipient, tweak_to_fr};
use crate::config::Config;
use crate::server::db::{Db, fr_to_u256};
use crate::server::state::State;
use crate::server::wallet::Wallet;
use crate::server::{BurnStep, IToken, IVault, IVerifier, SharedState, u256_to_fr};

use alloy::primitives::B256;
use ark_bn254::{Fq, Fr};
use ark_ff::{One, Zero}; // replace `use ark_bn254::Fr;` with the line above
use std::time::Instant;

use crate::zkp::TREE_DEPTH;
use crate::zkp::{
    RootTransitionCircuit, RootTransitionWitness, WithdrawCircuit, WithdrawWitness, poseidon2,
    prove_root_transition, prove_withdraw,
};

/// Max blocks per eth_getLogs call — under hosted-RPC range caps.
const LOG_CHUNK: u64 = 200;

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
    db: &Db,
) -> Result<(), Box<dyn std::error::Error>> {
    // Boot: full replay from the deployment block; afterwards incremental.
    let mut last_block = config.last_block;
    loop {
        // Phase 1: catch the mirror up to the finalized prefix [0..transferIndex).
        let mut next = state.lock().unwrap().clone(); // shared slot untouched on failure
        let p = prepare(&mut next, provider, config, db, last_block).await?;
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
        if let Some(work) = process_update_root(state, provider, wallet, config, last_block).await?
        {
            let tweak_fr = tweak_to_fr(work.tweak);
            if tweak_fr > Fr::zero() {
                let prev_tweak = tweak_fr - Fr::one();
                process_withdraws(&work, provider, wallet, config, prev_tweak).await?;
            }

            let count = process_withdraws(&work, provider, wallet, config, tweak_fr).await?;

            if count as u64 > work.rotate_threshold {
                rotate_tweak(provider, wallet, config).await?;
            }
        }

        // Phase 3: run payouts separately.
        if let Err(e) = payouts(provider, wallet, config, db).await {
            warn!(stage = "payout", error = %e, "phase 3 failed");
        }
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
    db: &Db,
    from_block: u64,
) -> Result<Prepared, Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let tweak: U256 = verifier.tweak().call().await?;
    s.tweak = tweak.to_be_bytes::<32>();

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

    hydrate_registrations(s, db).await?;

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
    sync_chain(
        &mut work,
        &events,
        reserved_chain,
        &mut |s, from, to, value| {
            witnesses.push(commit_transfer(s, from, to, value)?);
            Ok(())
        },
    )?;
    if work.chain.index() != reserved_index {
        return Err(format!(
            "reserved chain reached at index {} but reservedIndex is {reserved_index}",
            work.chain.index()
        )
        .into());
    }

    if witnesses.len() <= 1 {
        debug!(
            stage = "update_root",
            witnesses = witnesses.len(),
            "need >=2 witnesses for a batch; deferring"
        );
        return Ok(None);
    }

    submit_update_root(wallet, provider, config, z_0, witnesses).await?;

    Ok(Some(work))
}

async fn process_withdraws(
    work: &State,
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
    tweak: Fr,
) -> Result<usize, Box<dyn std::error::Error>> {
    let recip = recipient(work.chain_id, work.exchange_addr, fr_to_bytes32(tweak));
    let Some(witnesses) = withdraw_witnesses(work, recip) else {
        return Ok(0);
    };
    let count = witnesses.len();

    if count <= 1 {
        debug!(
            stage = "withdraw",
            count, "need >=2 receipts for a batch; deferring"
        );
        return Ok(count);
    }

    // Guard: skip the proof if the total is unchanged — everything already withdrawn.
    let total = witnesses
        .iter()
        .fold(U256::ZERO, |acc, w| acc + fr_to_u256(w.value));
    let already = IVerifier::new(config.verifier, provider)
        .totalWithdrawn(fr_to_u256(recip))
        .call()
        .await?;
    if total <= already {
        debug!(stage = "withdraw", count, "total unchanged — skip");
        return Ok(count);
    }

    let z_0 = vec![Fr::zero(), Fr::zero(), work.tree.root(), recip];

    submit_withdraws(wallet, provider, config, work, z_0, witnesses, tweak).await?;
    unwrap_after_withdraw(provider, wallet, config).await?;

    Ok(count)
}

/// Phase 3 — payouts: settle DB 'pending' user withdraws as token transfers.
/// Touches nothing from phases 1–2; sequential because every tx here shares
/// the exchange key.
async fn payouts(
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
    db: &Db,
) -> Result<(), Box<dyn std::error::Error>> {
    let pendings = db.pending_withdraws().await?;
    if pendings.is_empty() {
        return Ok(());
    }
    info!(
        stage = "payout",
        count = pendings.len(),
        "processing pending withdraws"
    );
    let token = IToken::new(config.token, provider);

    for w in pendings {
        let payout = w.amount;
        let ref_ = w.ref_.clone();
        let call = token.transfer(Address::from(w.destination), payout);
        let res = send_and_confirm(wallet, provider, config.token, call.calldata().clone()).await;
        match res {
            Ok(rc) if rc.status() => {
                db.settle_withdraw(&ref_, "succeeded", Some(rc.transaction_hash.0), None)
                    .await?;
                info!(stage = "payout", ref_ = %ref_, tx = %rc.transaction_hash, "paid out");
            }
            Ok(rc) => {
                db.settle_withdraw(&ref_, "failed", None, Some("payout reverted"))
                    .await?;
                warn!(stage = "payout", ref_ = %ref_, tx = %rc.transaction_hash, "payout reverted");
            }
            Err(e) => {
                // Unknown fate: the tx may have been broadcast before the
                // error. Do NOT settle 'failed' (that would free the
                // reservation while tokens may have moved) — leave 'pending'
                // for the operator to resolve.
                warn!(stage = "payout", ref_ = %ref_, error = %e, "outcome unknown — left pending");
            }
        }
    }
    Ok(())
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

/// Batch withdraw — Nova IVC per receipt + Groth16 decider. The fold starts
/// at cumulative base `z0_sum` (the already-withdrawn prefix sum), so the
/// contract mints exactly Σ witnesses on top of totalWithdrawn.
async fn submit_withdraws(
    wallet: &Wallet,
    provider: &impl Provider,
    config: &Config,
    work: &State,
    z_0: Vec<Fr>,
    witnesses: Vec<WithdrawWitness>,
    tweak: Fr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        stage = "withdraw",
        receipts = witnesses.len(),
        "proving batch withdraw (Nova + decider)"
    );

    let calldata = prove_withdraw(WithdrawCircuit::new(())?, z_0, witnesses)?;

    let proof: [U256; 34] = calldata[4..]
        .chunks_exact(32)
        .map(U256::from_be_slice)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|v: Vec<U256>| format!("withdraw proof has {} words, expected 34", v.len()))?;

    let verifier = IVerifier::new(config.verifier, provider);
    let call = verifier.withdraw(
        U256::from(work.chain_id),
        Address::from(work.exchange_addr),
        B256::from(fr_to_bytes32(tweak)),
        proof,
    );
    let rc = send_and_confirm(wallet, provider, config.verifier, call.calldata().clone()).await?;
    info!(stage = "withdraw", tx = %rc.transaction_hash, gas = rc.gas_used, "withdraw confirmed");

    Ok(())
}

/// Withdraw witnesses for deposits registered under `recipient` (one tweak's
/// namespace). Returns None when there are none for that recipient.
fn withdraw_witnesses(s: &State, recipient: Fr) -> Option<Vec<WithdrawWitness>> {
    let mut receipts: Vec<(usize, G2, G2, Fq, Fr, Fr)> = Vec::new();
    for (addr, ds) in &s.deposits {
        if s.recipient_by_addr.get(addr) != Some(&recipient) {
            continue; // prior tweak / unregistered — proven in its own batch
        }
        let (Some(&pk), Some(&(sig_r, sig_z)), Some(&salt), Some(&from)) = (
            s.pubkey_by_addr.get(addr),
            s.sig_by_addr.get(addr),
            s.salt_by_addr.get(addr),
            s.registered_from.get(addr),
        ) else {
            continue;
        };
        for &(_, value, idx) in ds {
            if (idx as u64) < from {
                continue; // pre-registration deposit — burned, never folded
            }
            receipts.push((idx, pk, sig_r, sig_z, salt, value));
        }
    }
    if receipts.is_empty() {
        return None;
    }
    receipts.sort_by_key(|r| r.0);
    Some(
        receipts
            .into_iter()
            .map(|(idx, pubkey, sig_r, sig_z, salt, value)| {
                let mut merkle_path = [Fr::zero(); TREE_DEPTH];
                merkle_path.copy_from_slice(&s.tree.proof(idx));
                WithdrawWitness {
                    pubkey,
                    sig_r,
                    sig_z,
                    salt,
                    value,
                    index: Fr::from(idx as u64),
                    merkle_path,
                }
            })
            .collect(),
    )
}

async fn unwrap_after_withdraw(
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = wallet.address();
    let zbal: U256 = IToken::new(config.token, provider)
        .balanceOf(exchange)
        .call()
        .await?;
    if zbal.is_zero() {
        return Ok(());
    }
    let vault = IVault::new(config.vault, provider);
    let call = vault.unwrap(zbal);
    let rc = send_and_confirm(wallet, provider, config.vault, call.calldata().clone()).await?;
    if !rc.status() {
        // Lost a race with a concurrent user unwrap — retry next interval.
        return Err(format!("unwrap reverted (tx {})", rc.transaction_hash).into());
    }
    info!(stage = "unwrap", amount = %zbal, tx = %rc.transaction_hash, "zUSDC -> USDC unwrapped");
    Ok(())
}

/// Apply one transfer to the working copy, recording the root-step witness.
fn commit_transfer(
    s: &mut State,
    from: [u8; 20],
    to: [u8; 20],
    value: Fr,
) -> Result<RootTransitionWitness, Box<dyn std::error::Error>> {
    let mut merkle_path = [Fr::zero(); TREE_DEPTH];
    merkle_path.copy_from_slice(&s.tree.proof_for_empty(s.tree.len()));
    let witness = RootTransitionWitness {
        to: address_to_fr(to),
        value,
        merkle_path,
    };
    apply_transfer(s, from, to, value)?;
    Ok(witness)
}

/// Latest registration per address, re-validated on load; malformed rows skipped.
async fn hydrate_registrations(s: &mut State, db: &Db) -> Result<(), Box<dyn std::error::Error>> {
    for r in db.latest_registrations().await? {
        let pk = G2Affine::new_unchecked(r.pubkey_x, r.pubkey_y);
        let rr = G2Affine::new_unchecked(r.sig_r_x, r.sig_r_y);
        if !(pk.is_on_curve() && rr.is_on_curve()) {
            warn!(stage = "prepare", addr = %hex::encode(r.address), "skipping invalid registration");
            continue;
        }
        s.pubkey_by_addr.insert(r.address, G2::from(pk));
        s.sig_by_addr.insert(r.address, (G2::from(rr), r.sig_z));
        s.salt_by_addr.insert(r.address, r.salt);
        s.registered_from
            .insert(r.address, r.registered_from as u64);
        s.recipient_by_addr.insert(r.address, r.recipient);
    }
    Ok(())
}

/// Replay one proven transfer: tree insert + hash-chain step + ledger entries.
fn apply_transfer(
    s: &mut State,
    from: [u8; 20],
    to: [u8; 20],
    value: Fr,
) -> Result<(), Box<dyn std::error::Error>> {
    let index = s.tree.len();
    s.tree.insert(poseidon2(address_to_fr(to), value)?);
    s.chain.apply(to, value);
    *s.credits.entry(to).or_default() += fr_to_u256(value);
    s.deposits.entry(to).or_default().push((from, value, index));
    Ok(())
}

/// Every BurnStep in [from_block, to_block] inclusive, ordered by
/// (block, log index). The carried chain value makes windows self-verifying
/// and exact-cut.
async fn fetch_chain_events(
    provider: &impl Provider,
    token: Address,
    from_block: u64,
    to_block: u64,
) -> Result<Vec<(u64, [u8; 20], [u8; 20], Fr, Fr)>, Box<dyn std::error::Error>> {
    let mut logs = Vec::new(); // (block, log_index, ...) until sorted
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
            logs.push((
                log.block_number.ok_or("log without block number")?,
                log.log_index.ok_or("log without log index")?,
                d.from.into_array(),
                d.to.into_array(),
                u256_to_fr(d.value),
                u256_to_fr(d.hashChain),
            ));
        }
        from = to + 1;
    }
    logs.sort_by_key(|e| (e.0, e.1));
    Ok(logs
        .into_iter()
        .map(|(b, _, f, t, v, h)| (b, f, t, v, h))
        .collect())
}

/// Advance the mirror along `events` until its hash chain equals `target`.
/// Position is recovered by chain value, so `events` may overlap history.
/// Returns the block of the target-carrying event, or None if already at target.
fn sync_chain(
    s: &mut State,
    events: &[(u64, [u8; 20], [u8; 20], Fr, Fr)],
    target: Fr,
    apply: &mut impl FnMut(&mut State, [u8; 20], [u8; 20], Fr) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    if s.chain.state() == target {
        return Ok(None); // already at the frontier
    }

    let mut it = events.iter().copied();
    let start = s.chain.state();

    // Loop 1 — find the starting state: skip up to and including the sync
    // event (the last transfer the mirror already ingested). Genesis has no
    // history, so there's nothing to skip.
    if !start.is_zero() {
        match it.find(|&(_, _, _, _, carried)| carried == start) {
            Some(_) => {} // `it` is now positioned just past the sync event
            None => return Err("sync point not in window: stale cursor or reorg".into()),
        }
    }

    // Loop 2 — apply from the carried state until the target chain is reached.
    for (blk, from, to, value, carried) in it {
        apply(s, from, to, value)?;
        if s.chain.state() != carried {
            return Err(format!(
                "chain mismatch at block {blk}: mirror out of sync (gap or reorg)"
            )
            .into());
        }
        if carried == target {
            return Ok(Some(blk));
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

pub fn log_recipient(state: &SharedState) {
    let s = state.lock().unwrap();
    let r = recipient(s.chain_id, s.exchange_addr, s.tweak);
    info!(stage = "boot", recipient = %r, "exchange recipient");
}

async fn rotate_tweak(
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let call = verifier.rotateTweak();
    let rc = send_and_confirm(wallet, provider, config.verifier, call.calldata().clone()).await?;
    info!(stage = "rotate", tx = %rc.transaction_hash, "tweak rotated");
    Ok(())
}

async fn advance_start_hash_chain(
    provider: &impl Provider,
    wallet: &Wallet,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = IVerifier::new(config.verifier, provider);
    let reserved: u64 = verifier.reservedIndex().call().await?.try_into()?;
    let transfer: u64 = verifier.transferIndex().call().await?.try_into()?;
    let start: u64 = verifier.startIndex().call().await?.try_into()?;
    if reserved.saturating_sub(transfer) < 2
        && reserved.saturating_sub(start) > config.settings.rotate_threshold
    {
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
