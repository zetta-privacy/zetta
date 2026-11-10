use alloy::providers::ProviderBuilder;
use spiral_rs::aligned_memory::AlignedMemory64;
use std::sync::{Arc, Mutex};
use zetta::server::oprf::ServerKey;
use zetta::server::pir::{build_cuckoo_db, build_level_db, build_level_dbs};

use zetta::config::{Config, load_settings};
use zetta::server::state::State;
use zetta::server::wallet::Wallet;
use zetta::server::{SharedState, worker};

use axum::{Json, Router, body::Bytes, extract::State as AxumState, routing::post};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

const PP_LEN: usize = 8_126_496; // == client pp_bytes.len()
const QUERY_LEN: usize = 16_416; // == client query.len()

/// body = pp ‖ num_queries(u8) ‖ [ level(u8) ‖ query ]*
/// resp = [ len(u32 LE) ‖ bytes ]*
async fn pir_handler(AxumState(s): AxumState<AppState>, body: Bytes) -> Vec<u8> {
    let pp = &body[..PP_LEN];
    let n = body[PP_LEN] as usize;
    let dbs = s.dbs.read().unwrap();
    let mut off = PP_LEN + 1;
    let mut out = Vec::new();
    for _ in 0..n {
        let level = body[off] as usize;
        let query = &body[off + 1..off + 1 + QUERY_LEN];
        off += 1 + QUERY_LEN;
        let params = if level == 32 {
            zetta::server::pir::cuckoo_params()
        } else {
            zetta::server::pir::level_params()
        };
        let r = zetta::server::pir::pir_respond(params, &dbs[level], pp, query);
        out.extend_from_slice(&(r.len() as u32).to_le_bytes());
        out.extend_from_slice(&r);
    }
    out
}

#[derive(Deserialize)]
struct EvaluateReq {
    blinded: String, // decimal Fr
}

#[derive(Serialize)]
struct EvaluateResp {
    evaluated: String, // decimal Fr
}

async fn oprf_evaluate(
    AxumState(s): AxumState<AppState>,
    Json(req): Json<EvaluateReq>,
) -> Json<EvaluateResp> {
    let blinded: ark_bn254::Fr = req.blinded.parse().unwrap();
    let evaluated = s.key.evaluate(&blinded);
    Json(EvaluateResp {
        evaluated: evaluated.to_string(),
    })
}

#[derive(Clone)]
struct AppState {
    dbs: Arc<RwLock<Vec<AlignedMemory64>>>,
    key: ServerKey,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zetta=info".into()),
        )
        .init();

    tracing::info!(stage = "boot", "loading config");
    let config = Config::from_env()?;

    tracing::info!(stage = "boot", "loading proving params");
    let t = std::time::Instant::now();
    zetta::zkp::cached_root_params()?;
    tracing::info!(stage = "boot", elapsed = ?t.elapsed(), "proving params loaded");

    let wallet = Wallet::new(
        &config.privy_app_id,
        &config.privy_app_secret,
        &config.privy_wallet_id,
        config.wallet_address,
        config.chain_id,
    )?;
    tracing::info!(stage = "boot", address = %wallet.address(), "operator wallet (privy)");
    // Read-only provider; every send/sign goes through the Privy wallet.
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse()?);

    let settings = load_settings()?;
    let state: SharedState = Arc::new(Mutex::new(State::new(config.chain_id, &settings)?));

    let oprf_key = ServerKey::random();
    let cuckoo = zetta::server::cuckoo::CuckooTable::build(
        &state.lock().unwrap().cuckoo_entries, // your Vec<([u8;20], u32, u64)>
        oprf_key.clone(),
        1 << 16, // table size (power of 2)
    );

    // build the 32 DBs from the tree's current history
    let pir_dbs: Arc<RwLock<Vec<AlignedMemory64>>> = Arc::new(RwLock::new({
        let mut dbs = build_level_dbs(&state.lock().unwrap().tree).to_vec();
        dbs.push(build_cuckoo_db(&cuckoo.table));
        dbs.push(build_level_db(&state.lock().unwrap().values));
        dbs
    }));

    tokio::spawn(zetta::server::pir::run(
        state.clone(),
        pir_dbs.clone(),
        oprf_key.clone(),
    ));

    let app = Router::new()
        .route("/pir", post(pir_handler))
        .route("/oprf/evaluate", post(oprf_evaluate))
        .with_state(AppState {
            dbs: pir_dbs,
            key: oprf_key,
        });

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port)).await?;

    // axum in background
    tokio::spawn(axum::serve(listener, app).into_future());

    // Worker runs forever; on any error, log and restart instead of exiting.
    loop {
        if let Err(e) = worker::run(&state, &provider, &wallet, &config).await {
            tracing::error!(error = %e, "worker error; restarting in 5s");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}
