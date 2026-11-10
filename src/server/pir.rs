use crate::server::SharedState;
use crate::server::cuckoo::{CuckooTable, Entry};
use crate::server::oprf::ServerKey;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use spiral_rs::aligned_memory::AlignedMemory64;
use spiral_rs::client::{PublicParameters, Query};
use spiral_rs::params::Params;
use spiral_rs::server::process_query;
use spiral_rs::util::params_from_json;
use std::sync::{Arc, RwLock};

/// Sibling levels 0..31 (the root at level 32 is public, not served).
pub const NUM_LEVELS: usize = 32;
pub const CUCKOO_LEVEL: usize = NUM_LEVELS; // 32
pub const VALUES_LEVEL: usize = NUM_LEVELS + 1; // 33
/// 2^(nu_1 + nu_2) entries per level.
const NUM_ITEMS: usize = 1 << (9 + 6); // 32768
const WORDS_PER_ITEM: usize = 32 / 8; // 4 u64 = 32 bytes

const LEAF_PARAMS: &str = r#"{
    "n": 2, "nu_1": 9, "nu_2": 6, "p": 256, "q2_bits": 20,
    "t_gsw": 8, "t_conv": 4, "t_exp_left": 8, "t_exp_right": 56,
    "instances": 1, "db_item_size": 32
}"#;

const CUCKOO_PARAMS: &str = r#"{
    "n": 2, "nu_1": 10, "nu_2": 6, "p": 256, "q2_bits": 20,
    "t_gsw": 8, "t_conv": 4, "t_exp_left": 8, "t_exp_right": 56,
    "instances": 1, "db_item_size": 32
}"#;

pub fn cuckoo_params() -> &'static Params {
    Box::leak(Box::new(params_from_json(CUCKOO_PARAMS)))
}

pub fn level_params() -> &'static Params {
    Box::leak(Box::new(params_from_json(LEAF_PARAMS)))
}

/// Append new leaf entries to the level DBs as the tree grows.
pub async fn run(state: SharedState, dbs: Arc<RwLock<Vec<AlignedMemory64>>>, key: ServerKey) {
    let mut last_written = state.lock().unwrap().tree.len();
    let mut last_cuckoo = 0usize;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let s = state.lock().unwrap();
        let new_len = s.tree.len();
        let cuckoo_len = s.cuckoo_entries.len();
        if new_len > last_written || cuckoo_len > last_cuckoo {
            let mut dbs = dbs.write().unwrap();
            if new_len > last_written {
                append_level_dbs(&mut dbs[..NUM_LEVELS], &s.tree, last_written);
                append_level_db(&mut dbs[VALUES_LEVEL], &s.values, last_written);
                last_written = new_len;
            }
            if cuckoo_len > last_cuckoo {
                let table = CuckooTable::build(&s.cuckoo_entries, key.clone(), 1 << 16);
                dbs[NUM_LEVELS] = build_cuckoo_db(&table.table);
                last_cuckoo = cuckoo_len;
            }
        }
    }
}

fn append_level_db(db: &mut AlignedMemory64, values: &[Fr], from: usize) {
    let slice = db.as_mut_slice();
    for k in from..values.len() {
        let be = values[k].into_bigint().to_bytes_be();
        for w in 0..WORDS_PER_ITEM {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&be[w * 8..(w + 1) * 8]);
            slice[k * WORDS_PER_ITEM + w] = u64::from_le_bytes(chunk);
        }
    }
}

/// Write only entries `from..tree.len()` into each level's DB.
pub fn append_level_dbs(dbs: &mut [AlignedMemory64], tree: &crate::tree::MerkleTree, from: usize) {
    for h in 0..NUM_LEVELS {
        append_level_db(&mut dbs[h], tree.level(h), from);
    }
}

/// Initial full build: one DB per level (0..NUM_LEVELS).
pub fn build_level_dbs(tree: &crate::tree::MerkleTree) -> [AlignedMemory64; NUM_LEVELS] {
    std::array::from_fn(|h| build_level_db(tree.level(h)))
}

pub fn build_level_db(values: &[Fr]) -> AlignedMemory64 {
    let mut db = AlignedMemory64::new(NUM_ITEMS * WORDS_PER_ITEM);
    append_level_db(&mut db, values, 0);
    db
}

/// Respond to one query against `db`.
pub fn pir_respond(
    params: &Params,
    db: &AlignedMemory64,
    pp_bytes: &[u8],
    query_bytes: &[u8],
) -> Vec<u8> {
    let pp = PublicParameters::deserialize(params, pp_bytes);
    let query = Query::deserialize(params, query_bytes);
    process_query(params, &pp, &query, db.as_slice())
}

/// One cuckoo slot → 32 bytes: address[20] || j[4] || leaf_index[8].
fn serialize_slot(slot: &Option<Entry>) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Some((addr, j, leaf)) = slot {
        out[0..20].copy_from_slice(addr);
        out[20..24].copy_from_slice(&j.to_be_bytes());
        out[24..32].copy_from_slice(&leaf.to_be_bytes());
    }
    out
}

/// Cuckoo table → one PIR DB (one 32-byte item per slot, empty = zeros).
pub fn build_cuckoo_db(table: &[Option<Entry>]) -> AlignedMemory64 {
    let mut db = AlignedMemory64::new(table.len() * (32 / 8));
    let slice = db.as_mut_slice();
    for (k, slot) in table.iter().enumerate() {
        let bytes = serialize_slot(slot);
        for w in 0..4 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[w * 8..(w + 1) * 8]);
            slice[k * 4 + w] = u64::from_le_bytes(chunk); // same packing as level DBs
        }
    }
    db
}

#[cfg(test)]
mod test {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use spiral_rs::client::Client;
    use spiral_rs::server::{generate_random_db_and_get_item, process_query};
    use spiral_rs::util::params_from_json;

    #[test]
    fn chacha_vector() {
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8); // 0x00..0x1f
        let mut rng = ChaCha20Rng::from_seed(seed);
        for _ in 0..3 {
            println!("{}", rng.next_u64());
        }
    }

    #[test]
    fn pir_vector() {
        let params = params_from_json(
            r#"{"n":2,"nu_1":9,"nu_2":6,"p":256,"q2_bits":20,"t_gsw":8,"t_conv":4,"t_exp_left":8,"t_exp_right":56,"instances":1,"db_item_size":32}"#,
        );

        let mut client = Client::init(&params);
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
        let pp = client.generate_keys_from_seed(seed);
        let pp_bytes = pp.serialize();
        println!("pp_len {}", pp_bytes.len());
        println!("pp_sum {}", pp_bytes.iter().map(|&b| b as u64).sum::<u64>());

        let query = client.generate_query(0);
        let qb = query.serialize();
        println!("query_len {}", qb.len());

        let (item, db) = generate_random_db_and_get_item(&params, 0);
        let response = process_query(&params, &pp, &query, db.as_slice());
        println!("response_len {}", response.len());

        let decoded = client.decode_response(response.as_slice());
        let p_bits = 8; // log2_ceil(256)
        let expected = item.to_vec(p_bits, params.modp_words_per_chunk());
        assert_eq!(decoded, expected);
        println!("roundtrip OK");
    }
}
