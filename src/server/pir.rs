use spiral_rs::aligned_memory::AlignedMemory64;
use spiral_rs::client::{PublicParameters, Query};
use spiral_rs::params::Params;
use spiral_rs::server::{load_db_from_seek, process_query};
use spiral_rs::util::params_from_json;
use std::fs::File;

/// 2^(nu_1+nu_2) leaves. Adjust nu_1/nu_2 to your leaf count.
const LEAF_PARAMS: &str = r#"{
    "n": 2, "nu_1": 9, "nu_2": 6, "p": 256, "q2_bits": 20,
    "t_gsw": 8, "t_conv": 4, "t_exp_left": 8, "t_exp_right": 56,
    "instances": 1, "db_item_size": 32
}"#;

fn params() -> &'static Params {
    Box::leak(Box::new(params_from_json(LEAF_PARAMS)))
}

/// Load the flat leaf file (num_items x 32 bytes, big-endian Fr per leaf).
pub fn load_leaf_db(path: &str) -> AlignedMemory64 {
    let mut f = File::open(path).expect("leaf db");
    load_db_from_seek(params(), &mut f)
}

/// Respond to one PIR query. pp_bytes = client's serialized PublicParameters.
pub fn pir_respond(db: &AlignedMemory64, pp_bytes: &[u8], query_bytes: &[u8]) -> Vec<u8> {
    let p = params();
    let pp = PublicParameters::deserialize(p, pp_bytes);
    let query = Query::deserialize(p, query_bytes);
    process_query(p, &pp, &query, db.as_slice())
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
