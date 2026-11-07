pub mod pir;
pub mod state;
pub mod wallet;
pub mod worker;

use crate::server::state::State;
use alloy::primitives::U256;
use alloy::providers::DynProvider;
use alloy::sol;
use ark_bn254::Fr;
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
        function startIndex() external view returns (uint256);
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
    pub provider: DynProvider, // wallet-backed, signs with PRIVATE_KEY
}

fn u256_to_fr(v: U256) -> Fr {
    let bytes: [u8; 32] = v.to_be_bytes();
    Fr::from_be_bytes_mod_order(&bytes)
}
