//! Redeploy RootTransitionVerifier / WithdrawVerifier only when their compiled
//! bytecode changed, then call Verifier.setVerifiers. Signs via Privy KMS.
//!
//! Env: PRIVY_APP_ID · PRIVY_APP_SECRET · PRIVY_WALLET_ID · PRIVY_WALLET_ADDRESS
//! Args: <network>   (base-sepolia | base-mainnet)
//! Run `forge build` first.

use alloy::primitives::{Address, Bytes, keccak256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::sol;
use alloy::sol_types::SolCall;
use serde_json::{Value, json};
use tracing::info;

use zetta::config::{Network, deployed_address};
use zetta::server::wallet::Wallet;

sol! {
    interface IVerifier {
        function rootTransitionVerifier() external view returns (address);
        function withdrawVerifier() external view returns (address);
        function setVerifiers(address root, address withdraw) external;
    }
}

const CACHE: &str = "artifacts/verifier-cache.json";

fn env(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(key).map_err(|_| format!("missing env {key}").into())
}

/// Fully-formed creation bytecode for a verifier (no libraries to link).
fn creation_bytecode(file: &str, contract: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let p = format!("contracts/out/{file}.sol/{contract}.json");
    let a: Value = serde_json::from_str(
        &std::fs::read_to_string(&p)
            .map_err(|e| format!("read {p}: {e} — run `forge build` first"))?,
    )?;
    let code = a["bytecode"]["object"]
        .as_str()
        .ok_or("bytecode.object missing")?
        .trim_start_matches("0x");
    Ok(hex::decode(code)?)
}

fn cache() -> Value {
    std::fs::read_to_string(CACHE)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

fn save_cache(root: &str, withdraw: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("artifacts")?;
    std::fs::write(
        CACHE,
        serde_json::to_string_pretty(&json!({
            "root": root, "withdraw": withdraw,
        }))?,
    )?;
    Ok(())
}

async fn wait_receipt(
    provider: &impl Provider,
    hash: alloy::primitives::B256,
) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
    for _ in 0..90 {
        if let Some(rc) = provider.get_transaction_receipt(hash).await? {
            return Ok(rc);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    Err(format!("tx {hash} not mined after 180s").into())
}

async fn deploy_verifier(
    wallet: &Wallet,
    provider: &impl Provider,
    file: &str,
    contract: &str,
) -> Result<Address, Box<dyn std::error::Error>> {
    let initcode = creation_bytecode(file, contract)?;
    let hash = wallet.deploy_tx(Bytes::from(initcode)).await?;
    let rc = wait_receipt(provider, hash).await?;
    if !rc.status() {
        return Err(format!("{contract} deployment reverted in {hash}").into());
    }
    let addr = rc
        .contract_address
        .ok_or("receipt without contract address")?;
    info!(contract = contract, address = %addr, "deployed");
    Ok(addr)
}

async fn read_addr(
    provider: &impl Provider,
    to: Address,
    data: Vec<u8>,
) -> Result<Address, Box<dyn std::error::Error>> {
    let raw = provider
        .call(TransactionRequest::default().to(to).input(data.into()))
        .await?;
    if raw.len() < 32 {
        return Err("short view call response".into());
    }
    Ok(Address::from_slice(&raw[raw.len() - 20..]))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    dotenv::dotenv().ok();

    let name = std::env::args()
        .nth(1)
        .ok_or("missing network — 'base-sepolia' or 'base-mainnet'")?;
    let network = Network::from_name(&name)?;
    let chain_id = network.chain_id();

    let provider = ProviderBuilder::new().connect_http(network.rpc_url().parse()?);
    if provider.get_chain_id().await? != chain_id {
        return Err("network chain_id does not match RPC endpoint".into());
    }

    let wallet = Wallet::new(
        &env("PRIVY_APP_ID")?,
        &env("PRIVY_APP_SECRET")?,
        &env("PRIVY_WALLET_ID")?,
        env("PRIVY_WALLET_ADDRESS")?.parse()?,
        chain_id,
    )?;

    // Hashes of the freshly-compiled verifiers.
    let root_code = creation_bytecode("RootTransitionVerifier", "NovaDecider")?;
    let withdraw_code = creation_bytecode("WithdrawVerifier", "NovaDecider")?;
    let root_hash = format!("{:x}", keccak256(&root_code));
    let withdraw_hash = format!("{:x}", keccak256(&withdraw_code));

    let prev = cache();
    let root_changed = prev["root"].as_str() != Some(root_hash.as_str());
    let withdraw_changed = prev["withdraw"].as_str() != Some(withdraw_hash.as_str());

    if !root_changed && !withdraw_changed {
        info!("verifier bytecode unchanged — nothing to do");
        return Ok(());
    }

    let verifier = deployed_address(chain_id, "Verifier")?;

    // Current on-chain verifier addresses (fall back to zero if unset).
    let cur_root = read_addr(
        &provider,
        verifier,
        IVerifier::rootTransitionVerifierCall {}.abi_encode(),
    )
    .await?;
    let cur_withdraw = read_addr(
        &provider,
        verifier,
        IVerifier::withdrawVerifierCall {}.abi_encode(),
    )
    .await?;

    let new_root = if root_changed {
        deploy_verifier(&wallet, &provider, "RootTransitionVerifier", "NovaDecider").await?
    } else {
        cur_root
    };
    let new_withdraw = if withdraw_changed {
        deploy_verifier(&wallet, &provider, "WithdrawVerifier", "NovaDecider").await?
    } else {
        cur_withdraw
    };

    let hash = wallet
        .send_tx(
            verifier,
            IVerifier::setVerifiersCall {
                root: new_root,
                withdraw: new_withdraw,
            }
            .abi_encode(),
            Some(300_000),
        )
        .await?;
    let rc = wait_receipt(&provider, hash).await?;
    if !rc.status() {
        return Err(format!("setVerifiers reverted in {hash}").into());
    }

    save_cache(&root_hash, &withdraw_hash)?;
    info!(root = %new_root, withdraw = %new_withdraw, "setVerifiers confirmed");
    Ok(())
}
