use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub rotate_threshold: u64,
    pub tweak: u64,
    pub poll_interval_secs: u64,
    pub max_users: i64,
    pub max_cards_per_user: i64,
    pub card_limit_window_days: i64,
}

const SETTINGS_PATH: &str = "settings.json";

pub fn load_settings() -> Result<Settings, Box<dyn std::error::Error>> {
    let s = std::fs::read_to_string(SETTINGS_PATH)?;
    Ok(serde_json::from_str(&s)?)
}

#[derive(Clone, Copy)]
pub enum Network {
    BaseSepolia,
    BaseMainnet,
}

impl Network {
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::BaseSepolia => 84532,
            Self::BaseMainnet => 8453,
        }
    }
    pub fn rpc_url(&self) -> &'static str {
        match self {
            Self::BaseSepolia => "https://sepolia.base.org",
            Self::BaseMainnet => "https://mainnet.base.org",
        }
    }
    pub fn laso_url(&self) -> &'static str {
        match self {
            Self::BaseSepolia => "http://localhost:4100",
            Self::BaseMainnet => "https://laso.finance",
        }
    }

    pub fn from_name(name: &str) -> Result<Self, String> {
        match name {
            "base-sepolia" => Ok(Self::BaseSepolia),
            "base-mainnet" => Ok(Self::BaseMainnet),
            _ => Err(format!(
                "unknown network '{name}' — pass 'base-sepolia' or 'base-mainnet'"
            )),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::BaseSepolia => 3000,
            Self::BaseMainnet => 3001,
        }
    }
}

struct Cli {
    network: Network,
}

/// CLI: `base-sepolia | base-mainnet`.
fn parse_cli() -> Result<Cli, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = args
        .next()
        .ok_or("missing network argument — pass 'base-sepolia' or 'base-mainnet'")?;
    Ok(Cli {
        network: Network::from_name(&name)?,
    })
}

pub struct Config {
    pub rpc_url: String,
    pub database_url: String,
    /// Card provider base URL (mock-laso in dev, https://laso.finance in prod).
    pub laso_url: String,
    pub token: Address,
    pub verifier: Address,
    pub vault: Address,
    pub port: u16,
    pub chain_id: u64,
    pub last_block: u64,
    // Privy wallet credentials
    pub privy_app_id: String,
    pub privy_app_secret: String,
    pub privy_wallet_id: String,
    pub wallet_address: Address,
    // Settings
    pub settings: Settings,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv::dotenv().ok();
        let cli = parse_cli()?;
        let chain_id = cli.network.chain_id();
        Ok(Self {
            rpc_url: cli.network.rpc_url().to_string(),
            database_url: std::env::var("DATABASE_URL")?,
            laso_url: cli.network.laso_url().to_string(),
            token: deployed_address(chain_id, "zERC20")?,
            verifier: deployed_address(chain_id, "Verifier")?,
            vault: deployed_address(chain_id, "USDCVault")?,
            privy_app_id: std::env::var("PRIVY_APP_ID")?,
            privy_app_secret: std::env::var("PRIVY_APP_SECRET")?,
            privy_wallet_id: std::env::var("PRIVY_WALLET_ID")?,
            wallet_address: std::env::var("PRIVY_WALLET_ADDRESS")?.parse()?,
            port: cli.network.port(),
            chain_id,
            last_block: deployment_block(chain_id, "zERC20")?,
            settings: load_settings()?,
        })
    }
}

/// TWEAK is a decimal integer ("0", "1", ...), encoded big-endian into 32 bytes.
pub fn parse_tweak(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let n = alloy::primitives::U256::from_str_radix(s.trim(), 10)?;
    Ok(n.to_be_bytes::<32>())
}

fn load_broadcast(chain_id: u64) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = format!("broadcast/Deploy.s.sol/{chain_id}/run-latest.json");
    Ok(serde_json::from_str(&std::fs::read_to_string(&path)?)?)
}

/// Address of a CREATE'd contract from `forge script --broadcast`.
pub fn deployed_address(
    chain_id: u64,
    contract_name: &str,
) -> Result<Address, Box<dyn std::error::Error>> {
    let json = load_broadcast(chain_id)?;
    let addr = json["transactions"]
        .as_array()
        .ok_or("no transactions in broadcast")?
        .iter()
        .find(|tx| tx["transactionType"] == "CREATE" && tx["contractName"] == contract_name)
        .and_then(|tx| tx["contractAddress"].as_str())
        .ok_or_else(|| format!("no {contract_name} deployment in broadcast"))?;
    Ok(addr.parse()?)
}

/// Block number of the deployment tx for a contract.
pub fn deployment_block(
    chain_id: u64,
    contract_name: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let json = load_broadcast(chain_id)?;
    let hash = json["transactions"]
        .as_array()
        .ok_or("no transactions in broadcast")?
        .iter()
        .find(|tx| tx["transactionType"] == "CREATE" && tx["contractName"] == contract_name)
        .and_then(|tx| tx["hash"].as_str())
        .ok_or_else(|| format!("no {contract_name} deployment in broadcast"))?;
    let block_hex = json["receipts"]
        .as_array()
        .ok_or("no receipts in broadcast")?
        .iter()
        .find(|r| r["transactionHash"].as_str() == Some(hash))
        .and_then(|r| r["blockNumber"].as_str())
        .ok_or("no receipt for deployment")?;
    Ok(u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)?)
}
