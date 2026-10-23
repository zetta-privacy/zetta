use std::{fs, path::Path};

use zetta::zkp::{
    ARTIFACTS_DIR, read_root_params, read_withdraw_params, render_root_transition_verifier,
    render_withdraw_verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = Path::new("contracts/src/verifiers");
    let artifacts = Path::new(ARTIFACTS_DIR);
    fs::create_dir_all(out_dir)?;

    println!("rendering verifiers from existing artifacts...");

    fs::write(
        out_dir.join("RootTransitionVerifier.sol"),
        render_root_transition_verifier(&read_root_params(artifacts)?.decider_vp)?,
    )?;
    fs::write(
        out_dir.join("WithdrawVerifier.sol"),
        render_withdraw_verifier(&read_withdraw_params(artifacts)?.decider_vp)?,
    )?;

    println!("done");
    Ok(())
}
