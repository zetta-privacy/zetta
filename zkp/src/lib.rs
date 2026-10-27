mod poseidon;
mod root;
mod withdraw;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use folding_schemes::commitment::kzg::KZG;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::nova::decider_eth::Decider as DeciderEth;
use folding_schemes::folding::nova::decider_eth::DeciderEthCircuit;
use folding_schemes::folding::nova::decider_eth::VerifierParam;
use folding_schemes::folding::nova::{Nova, PreprocessorParam};
use folding_schemes::folding::traits::Dummy;
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Decider, FoldingScheme};
use std::path::{Path, PathBuf};
use tracing::info;

pub use poseidon::*;
pub use root::*;
pub use withdraw::*;

use solidity_verifiers::NovaCycleFoldVerifierKey;
use solidity_verifiers::calldata::{
    NovaVerificationMode, prepare_calldata_for_nova_cyclefold_verifier,
};
use solidity_verifiers::verifiers::nova_cyclefold::get_decider_template_for_cyclefold_decider;

pub const ARTIFACTS_DIR: &str = "artifacts";
pub const TREE_DEPTH: usize = 32;

pub type RootN = Nova<G1, G2, RootTransitionCircuit, KZG<'static, Bn254>, Pedersen<G2>, false>;
pub type RootD = DeciderEth<
    G1,
    G2,
    RootTransitionCircuit,
    KZG<'static, Bn254>,
    Pedersen<G2>,
    Groth16<Bn254>,
    RootN,
>;
pub type WithdrawN = Nova<G1, G2, WithdrawCircuit, KZG<'static, Bn254>, Pedersen<G2>, false>;
pub type WithdrawD = DeciderEth<
    G1,
    G2,
    WithdrawCircuit,
    KZG<'static, Bn254>,
    Pedersen<G2>,
    Groth16<Bn254>,
    WithdrawN,
>;

pub type RootDeciderVp = <RootD as Decider<G1, G2, RootTransitionCircuit, RootN>>::VerifierParam;
pub type WithdrawDeciderVp =
    <WithdrawD as Decider<G1, G2, WithdrawCircuit, WithdrawN>>::VerifierParam;

// ---- fs helpers ----

fn to_bytes(v: &impl CanonicalSerialize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = vec![];
    v.serialize_uncompressed(&mut buf)?;
    Ok(buf)
}

/// Pure read. Missing file is an error pointing at the explicit generator.
fn read_bytes(path: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    std::fs::read(path).map_err(|e| {
        format!(
            "{}: {e} — run `cargo run --release --bin gen-artifacts` first",
            path.display()
        )
        .into()
    })
}

/// Pure write. Fails rather than overwriting existing artifacts, so key
// material is never silently rotated (the old load-or-generate path did).
fn write_new(path: &PathBuf, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            format!(
                "{}: {e} (refusing to overwrite — `rm -rf artifacts/` to regenerate)",
                path.display()
            )
        })?;
    f.write_all(bytes)?;
    Ok(())
}

// ---- Nova + decider artifact families (root / withdraw) ----

macro_rules! nova_artifact_set {
    ($prefix:literal, $holder:ident, $fc:ty, $n:ty, $d:ty, $fc_params:expr,
     create = $create:ident, read = $read:ident, write = $write:ident, cached = $cached:ident) => {
        pub struct $holder {
            pub nova_params: (
                <$n as FoldingScheme<G1, G2, $fc>>::ProverParam,
                <$n as FoldingScheme<G1, G2, $fc>>::VerifierParam,
            ),
            pub decider_pp: <$d as Decider<G1, G2, $fc, $n>>::ProverParam,
            pub decider_vp: <$d as Decider<G1, G2, $fc, $n>>::VerifierParam,
        }

        /// CREATE: fresh random params in memory. No fs, no cache.
        pub fn $create() -> Result<$holder, Box<dyn std::error::Error>> {
            let f_circuit = <$fc>::new($fc_params.clone())?;
            let poseidon_config = poseidon_canonical_config::<Fr>();
            let mut rng = ark_std::rand::rngs::OsRng;

            let prep = PreprocessorParam::new(poseidon_config, f_circuit.clone());
            let nova_params = <$n as FoldingScheme<G1, G2, $fc>>::preprocess(&mut rng, &prep)?;
            let (decider_pp, decider_vp) = <$d as Decider<G1, G2, $fc, $n>>::preprocess(
                &mut rng,
                (nova_params.clone(), f_circuit.state_len()),
            )?;
            Ok($holder {
                nova_params,
                decider_pp,
                decider_vp,
            })
        }

        /// SAVE TO FS: writes the four artifact files. Never generates, never overwrites.
        pub fn $write(dir: &Path, p: &$holder) -> Result<(), Box<dyn std::error::Error>> {
            std::fs::create_dir_all(dir)?;
            write_new(
                &dir.join(concat!($prefix, "_nova_pp.bin")),
                &to_bytes(&p.nova_params.0)?,
            )?;
            write_new(
                &dir.join(concat!($prefix, "_nova_vp.bin")),
                &to_bytes(&p.nova_params.1)?,
            )?;
            write_new(
                &dir.join(concat!($prefix, "_decider_pp.bin")),
                &to_bytes(&p.decider_pp)?,
            )?;
            write_new(
                &dir.join(concat!($prefix, "_decider_vp.bin")),
                &to_bytes(&p.decider_vp)?,
            )?;
            Ok(())
        }

        /// LOAD FROM FS: reads the four artifact files. Never generates.
        pub fn $read(dir: &Path) -> Result<$holder, Box<dyn std::error::Error>> {
            let nova_pp =
                <$n as FoldingScheme<G1, G2, $fc>>::ProverParam::deserialize_uncompressed(
                    &mut read_bytes(&dir.join(concat!($prefix, "_nova_pp.bin")))?.as_slice(),
                )?;
            let nova_vp = <$n as FoldingScheme<G1, G2, $fc>>::vp_deserialize_with_mode(
                &mut read_bytes(&dir.join(concat!($prefix, "_nova_vp.bin")))?.as_slice(),
                ark_serialize::Compress::No,
                ark_serialize::Validate::No,
                $fc_params.clone(),
            )?;
            let decider_pp =
                <$d as Decider<G1, G2, $fc, $n>>::ProverParam::deserialize_uncompressed(
                    &mut read_bytes(&dir.join(concat!($prefix, "_decider_pp.bin")))?.as_slice(),
                )?;
            let decider_vp =
                <$d as Decider<G1, G2, $fc, $n>>::VerifierParam::deserialize_uncompressed(
                    &mut read_bytes(&dir.join(concat!($prefix, "_decider_vp.bin")))?.as_slice(),
                )?;
            Ok($holder {
                nova_params: (nova_pp, nova_vp),
                decider_pp,
                decider_vp,
            })
        }

        /// SAVE TO MEMORY: process-wide cache over the fs load. Never generates.
        pub fn $cached() -> Result<&'static $holder, Box<dyn std::error::Error>> {
            static CACHE: std::sync::OnceLock<Result<$holder, String>> = std::sync::OnceLock::new();
            CACHE
                .get_or_init(|| $read(Path::new(ARTIFACTS_DIR)).map_err(|e| e.to_string()))
                .as_ref()
                .map_err(|e| e.clone().into())
        }
    };
}

nova_artifact_set!(
    "root",
    RootParams,
    RootTransitionCircuit,
    RootN,
    RootD,
    (),
    create = create_root_params,
    read = read_root_params,
    write = write_root_params,
    cached = cached_root_params
);
nova_artifact_set!(
    "withdraw",
    WithdrawParams,
    WithdrawCircuit,
    WithdrawN,
    WithdrawD,
    (),
    create = create_withdraw_params,
    read = read_withdraw_params,
    write = write_withdraw_params,
    cached = cached_withdraw_params
);

// ---- proving ----

macro_rules! prove_for {
    ($name:ident, $acc:ident, $fc:ty, $n:ty, $d:ty) => {
        pub fn $name(
            f_circuit: $fc,
            z_0: Vec<Fr>,
            external_inputs: Vec<<$fc as FCircuit<Fr>>::ExternalInputs>,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            use std::time::Instant;

            let load_start = Instant::now();
            let params = $acc()?;
            info!(proof = stringify!($name), phase = "load_params", elapsed = ?load_start.elapsed());
            let rng = ark_std::rand::rngs::OsRng;

            let init_start = Instant::now();
            let mut nova =
                <$n as FoldingScheme<G1, G2, $fc>>::init(&params.nova_params, f_circuit.clone(), z_0)?;
            eprintln!("[{}] init={:?}", stringify!($name), init_start.elapsed());

            let n_steps = external_inputs.len();
            let fold_start = Instant::now();
            for ext in external_inputs {
                nova.prove_step(rng, ext, None)?;
            }
            let fold_elapsed = fold_start.elapsed();

            let decider_start = Instant::now();
            let proof = <$d as Decider<G1, G2, $fc, $n>>::prove(rng, params.decider_pp.clone(), nova.clone())?;
            let decider_elapsed = decider_start.elapsed();

            let avg = match n_steps {
                0 => "n/a".to_string(),
                n => format!("{:?}/step", fold_elapsed / n as u32),
            };
            eprintln!(
                "[{}] steps={} fold={:?} ({}) decider={:?}",
                stringify!($name),
                n_steps,
                fold_elapsed,
                avg,
                decider_elapsed,
            );

            let cal_start = Instant::now();
            let calldata = prepare_calldata_for_nova_cyclefold_verifier(
                NovaVerificationMode::Opaque,
                nova.i,
                nova.z_0,
                nova.z_i,
                &nova.U_i,
                &nova.u_i,
                &proof,
            )?;
            eprintln!(
                "[{}] prepare_calldata={:?}",
                stringify!($name),
                cal_start.elapsed()
            );

            Ok(calldata)
        }
    };
}

prove_for!(
    prove_root_transition,
    cached_root_params,
    RootTransitionCircuit,
    RootN,
    RootD
);
prove_for!(
    prove_withdraw,
    cached_withdraw_params,
    WithdrawCircuit,
    WithdrawN,
    WithdrawD
);

// ---- decider verifier rendering (pure: key -> Solidity) ----

macro_rules! render_decider_verifier_for {
    ($name:ident, $dvp:ty, $state_len:expr) => {
        pub fn $name(decider_vp: &$dvp) -> Result<String, Box<dyn std::error::Error>> {
            let nova_cyclefold_vk =
                NovaCycleFoldVerifierKey::from((decider_vp.clone(), $state_len));
            Ok(get_decider_template_for_cyclefold_decider(
                nova_cyclefold_vk,
            ))
        }
    };
}

render_decider_verifier_for!(render_root_transition_verifier, RootDeciderVp, 3);
render_decider_verifier_for!(render_withdraw_verifier, WithdrawDeciderVp, 4);

macro_rules! decider_circuit_for {
    ($name:ident, $fc:ty, $n:ty, $state_len:expr) => {
        pub fn $name() -> Result<DeciderEthCircuit<G1, G2>, Box<dyn std::error::Error>> {
            let f_circuit = <$fc>::new(())?;
            let poseidon_config = poseidon_canonical_config::<Fr>();
            let mut rng = ark_std::rand::rngs::OsRng;
            let prep = PreprocessorParam::new(poseidon_config, f_circuit.clone());
            let (nova_pp, nova_vp) =
                <$n as FoldingScheme<G1, G2, $fc>>::preprocess(&mut rng, &prep)?;

            Ok(DeciderEthCircuit::<G1, G2>::dummy((
                nova_vp.r1cs,
                nova_vp.cf_r1cs,
                nova_pp.cf_cs_pp,
                nova_pp.poseidon_config,
                (),
                (),
                $state_len,
                2,
            )))
        }
    };
}

decider_circuit_for!(root_decider_circuit, RootTransitionCircuit, RootN, 3);
decider_circuit_for!(withdraw_decider_circuit, WithdrawCircuit, WithdrawN, 4);

macro_rules! setup_struct {
    ($name:ident, $fc:ty, $n:ty, $d:ty, $holder:ident, $state_len:expr) => {
        pub struct $name {
            pub nova_pp: <$n as FoldingScheme<G1, G2, $fc>>::ProverParam,
            pub nova_vp: <$n as FoldingScheme<G1, G2, $fc>>::VerifierParam,
        }

        impl $name {
            pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
                let f_circuit = <$fc>::new(())?;
                let poseidon_config = poseidon_canonical_config::<Fr>();
                let mut rng = ark_std::rand::rngs::OsRng;
                let prep = PreprocessorParam::new(poseidon_config, f_circuit);
                let (nova_pp, nova_vp) =
                    <$n as FoldingScheme<G1, G2, $fc>>::preprocess(&mut rng, &prep)?;
                Ok(Self { nova_pp, nova_vp })
            }

            pub fn decider_circuit(&self) -> DeciderEthCircuit<G1, G2> {
                DeciderEthCircuit::<G1, G2>::dummy((
                    self.nova_vp.r1cs.clone(),
                    self.nova_vp.cf_r1cs.clone(),
                    self.nova_pp.cf_cs_pp.clone(),
                    self.nova_pp.poseidon_config.clone(),
                    (),
                    (),
                    $state_len,
                    2,
                ))
            }

            pub fn finish(
                self,
                pk: <Groth16<Bn254> as ark_snark::SNARK<Fr>>::ProvingKey,
                vk: <Groth16<Bn254> as ark_snark::SNARK<Fr>>::VerifyingKey,
            ) -> $holder {
                let pp_hash = self.nova_vp.pp_hash().unwrap();
                let decider_pp = (pk, self.nova_pp.cs_pp.clone());
                let decider_vp = VerifierParam {
                    pp_hash,
                    snark_vp: vk,
                    cs_vp: self.nova_vp.cs_vp.clone(),
                };
                $holder {
                    nova_params: (self.nova_pp, self.nova_vp),
                    decider_pp,
                    decider_vp,
                }
            }

            pub fn save(&self, path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
                use ark_serialize::CanonicalSerialize;
                let mut buf = vec![];
                self.nova_pp.serialize_uncompressed(&mut buf)?;
                self.nova_vp.serialize_uncompressed(&mut buf)?;
                std::fs::write(path, buf)?;
                Ok(())
            }

            pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
                use ark_serialize::CanonicalDeserialize;
                let bytes = std::fs::read(path)?;
                let mut reader = &bytes[..];
                let nova_pp =
                    <$n as FoldingScheme<G1, G2, $fc>>::ProverParam::deserialize_uncompressed(
                        &mut reader,
                    )?;
                let nova_vp = <$n as FoldingScheme<G1, G2, $fc>>::vp_deserialize_with_mode(
                    &mut reader,
                    ark_serialize::Compress::No,
                    ark_serialize::Validate::No,
                    (),
                )?;
                Ok(Self { nova_pp, nova_vp })
            }
        }
    };
}

setup_struct!(
    RootSetup,
    RootTransitionCircuit,
    RootN,
    RootD,
    RootParams,
    3
);
setup_struct!(
    WithdrawSetup,
    WithdrawCircuit,
    WithdrawN,
    WithdrawD,
    WithdrawParams,
    4
);
