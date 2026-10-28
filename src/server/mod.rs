pub mod api;
pub mod db;
pub mod laso;
pub mod state;
pub mod wallet;
pub mod worker;

use crate::server::db::Db;
use crate::server::state::State;
use alloy::primitives::U256;
use alloy::providers::DynProvider;
use alloy::sol;
use ark_bn254::{Fq, Fr};
use ark_ff::PrimeField;
use std::sync::{Arc, Mutex};

sol! {
    #[sol(rpc)]
    interface IToken {
        function transfer(address to, uint256 value) external returns (bool);
        function balanceOf(address) external view returns (uint256);
    }
    event Transfer(address indexed from, address indexed to, uint256 value);
    event BurnStep(address indexed from, address indexed to, uint256 value, uint256 hashChain);
}

sol! {
    #[sol(rpc)]
    interface IVerifier {
        function transferRoot() external view returns (uint256);
        function transferHashChain() external view returns (uint256);
        function transferIndex() external view returns (uint256);
        function totalWithdrawn(uint256) external view returns (uint256);
        function withdrawIndex(uint256) external view returns (uint256);   // <-- add
        function reservedIndex() external view returns (uint256);
        function reservedHashChain() external view returns (uint256);
        function reserveHashChain() external;
        function updateRoot(uint256[32] proof) external;
        function updateRootSingle(uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[6] pubSignals) external;
        function withdraw(uint256 chainId, address addr, bytes32 tweak, uint256[34] proof) external;
        function updateStartHashChain() external;
        function tweak() external view returns (uint256);
        function rotateTweak() external;
    }
}

sol! {
    #[sol(rpc)]
    interface IVault {
        function USDC() external view returns (address);
        function unwrap(uint256 amount) external;
    }
}

pub type SharedState = Arc<Mutex<State>>;

#[derive(Clone)]
pub struct AppState {
    pub state: SharedState,
    pub db: Db,
    pub provider: DynProvider, // wallet-backed, signs with PRIVATE_KEY
    pub laso: laso::LasoClient,
}

fn u256_to_fr(v: U256) -> Fr {
    let bytes: [u8; 32] = v.to_be_bytes();
    Fr::from_be_bytes_mod_order(&bytes)
}

fn parse_hex20(s: &str) -> Result<[u8; 20], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "expected 20 bytes".to_string())
}

fn parse_decimal_fr(s: &str) -> Result<Fr, String> {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).ok_or("invalid decimal")?;
    Ok(Fr::from_be_bytes_mod_order(&n.to_bytes_be()))
}

fn parse_decimal_fq(s: &str) -> Result<Fq, String> {
    let n = num_bigint::BigUint::parse_bytes(s.as_bytes(), 10).ok_or("invalid decimal")?;
    Ok(Fq::from_be_bytes_mod_order(&n.to_bytes_be()))
}
