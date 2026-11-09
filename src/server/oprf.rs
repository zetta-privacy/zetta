//! OPRF over the bn254 scalar field: PRF(k, x) = H2(x, H1(x)^k).
//! Client blinds H1(x), server evaluates with k, client unblinds + finalizes.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_std::rand::thread_rng;
use sha3::{Digest, Keccak256};

/// H1: hash a byte string into Fr.
fn hash_to_field(x: &[u8]) -> Fr {
    let h = Keccak256::digest(x);
    Fr::from_be_bytes_mod_order(&h)
}

/// H2: derive 32 output bytes from (x, D).
fn finalize_hash(x: &[u8], d: Fr) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(x);
    h.update(d.into_bigint().to_bytes_be());
    h.finalize().into()
}

/// Server's secret key k.
#[derive(Clone)]
pub struct ServerKey(Fr);

impl ServerKey {
    pub fn random() -> Self {
        Self(Fr::rand(&mut thread_rng()))
    }

    /// Direct PRF (server builds the table; it knows k, no blinding).
    pub fn prf(&self, x: &[u8]) -> [u8; 32] {
        let d = hash_to_field(x).pow(self.0.into_bigint());
        finalize_hash(x, d)
    }

    /// OPRF evaluation on a blinded element: C = B^k.
    pub fn evaluate(&self, blinded: &Fr) -> Fr {
        blinded.pow(self.0.into_bigint())
    }
}

/// Client's blinding state (kept secret).
pub struct BlindState {
    r: Fr,
}

/// Client: B = H1(x) * r. Send `B` to the server, keep `BlindState`.
pub fn blind(x: &[u8]) -> (Fr, BlindState) {
    let r = Fr::rand(&mut thread_rng());
    (hash_to_field(x) * r, BlindState { r })
}

/// Client: PRF(k, x) = H2(x, C^(1/r)). `evaluated` is C from the server.
pub fn finalize(x: &[u8], state: &BlindState, evaluated: &Fr) -> [u8; 32] {
    let d = evaluated.pow(state.r.inverse().unwrap().into_bigint());
    finalize_hash(x, d)
}

/// Split a 32-byte PRF into two Cuckoo positions, mod table size m.
pub fn positions(prf: &[u8; 32], m: usize) -> (usize, usize) {
    let lo = u128::from_le_bytes(prf[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(prf[16..].try_into().unwrap());
    ((lo as usize) % m, (hi as usize) % m)
}
