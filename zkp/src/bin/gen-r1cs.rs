use std::path::Path;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::gr1cs::ConstraintSynthesizer;
use folding_schemes::arith::Arith;
use serde_json::Value;
use zkp::{ARTIFACTS_DIR, root_decider_circuit, withdraw_decider_circuit};

fn row_to_json(row: &[(Fr, usize)]) -> Value {
    let mut map = serde_json::Map::new();
    for (coeff, idx) in row {
        map.insert(
            idx.to_string(),
            serde_json::json!(coeff.into_bigint().to_string()),
        );
    }
    Value::Object(map)
}

fn export_r1cs<C: ConstraintSynthesizer<Fr>>(
    path: &Path,
    circuit: C,
) -> Result<(), Box<dyn std::error::Error>> {
    let r1cs = folding_schemes::folding::nova::get_r1cs_from_cs::<Fr>(circuit)?;

    let n_cols = r1cs.A.n_cols;
    let n_pub = r1cs.n_public_inputs();

    let constraints: Vec<Value> = (0..r1cs.A.n_rows)
        .map(|i| {
            serde_json::json!([
                row_to_json(&r1cs.A.coeffs[i]),
                row_to_json(&r1cs.B.coeffs[i]),
                row_to_json(&r1cs.C.coeffs[i]),
            ])
        })
        .collect();

    let json = serde_json::json!({
        "n8": 32,
        "prime": Fr::MODULUS.to_string(),
        "nVars": n_cols,
        "nOutputs": 0,
        "nPubInputs": n_pub,
        "nPrvInputs": n_cols - 1 - n_pub,
        "nLabels": n_cols,
        "constraints": constraints,
    });

    std::fs::write(path, serde_json::to_string_pretty(&json)?)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(ARTIFACTS_DIR);
    std::fs::create_dir_all(dir)?;

    println!("exporting root decider R1CS (huge, slow)...");
    export_r1cs(&dir.join("root_decider.r1cs.json"), root_decider_circuit()?)?;

    println!("exporting withdraw decider R1CS (huge, slow)...");
    export_r1cs(
        &dir.join("withdraw_decider.r1cs.json"),
        withdraw_decider_circuit()?,
    )?;

    println!("done");
    Ok(())
}
