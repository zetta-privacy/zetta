use alloy::providers::{Provider, ProviderBuilder};
use std::sync::{Arc, Mutex};

use zetta::config::Config;
use zetta::server::db::Db;
use zetta::server::state::State;
use zetta::server::wallet::Wallet;
use zetta::server::{AppState, SharedState, api, worker};

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
    zetta::zkp::cached_withdraw_params()?;
    tracing::info!(stage = "boot", elapsed = ?t.elapsed(), "proving params loaded");

    let wallet = Wallet::new(
        &config.privy_app_id,
        &config.privy_app_secret,
        &config.privy_wallet_id,
        config.wallet_address,
        config.chain_id,
    )?;
    tracing::info!(stage = "boot", address = %wallet.address(), "operator wallet (privy)");
    let exchange_addr = wallet.address().into_array();
    let laso = zetta::server::laso::LasoClient::new(&config.laso_url, wallet.clone());
    // Read-only provider; every send/sign goes through the Privy wallet.
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse()?);

    let db = Db::open(&config.database_url).await?;
    let settings = db.load_settings().await?;

    let state: SharedState = Arc::new(Mutex::new(State::new(
        config.chain_id,
        exchange_addr,
        &settings,
    )?));
    worker::log_recipient(&state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.port))
        .await
        .map_err(|e| {
            format!(
                "bind :{} failed: {e} — stale zetta process? kill it: kill $(lsof -ti :{})",
                config.port, config.port
            )
        })?;
    api::spawn_http_server(
        AppState {
            state: state.clone(),
            db: db.clone(),
            provider: provider.clone().erased(),
            laso,
        },
        listener,
    );
    tracing::info!(stage = "boot", port = config.port, "HTTP server bound");

    // Worker runs forever; on any error, log and restart instead of exiting.
    loop {
        if let Err(e) = worker::run(&state, &provider, &wallet, &config, &db).await {
            tracing::error!(error = %e, "worker error; restarting in 5s");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}
