use std::path::Path;

use zetta::{
    ARTIFACTS_DIR, create_root_params, create_withdraw_params, write_root_params,
    write_withdraw_params,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(ARTIFACTS_DIR);

    println!("generating root-transition params (slow)...");
    write_root_params(dir, &create_root_params()?)?;

    println!("generating withdraw params (slow)...");
    write_withdraw_params(dir, &create_withdraw_params()?)?;

    println!("artifacts written to {}", dir.display());
    println!("next: cargo run --release --bin gen-verifiers && redeploy");
    Ok(())
}
