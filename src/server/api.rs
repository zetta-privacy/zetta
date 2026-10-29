use axum::extract::{Path, State as AxumState};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use alloy::primitives::U256;
use ark_bn254::{Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::{Affine as G2Affine, Projective as G2};

use crate::burn::{recipient, trim_to_160};
use crate::server::db::{Registration, fr_to_u256, unix_now};
use crate::server::laso::wei_to_usd;
use crate::server::state::State;
use crate::server::{AppState, parse_decimal_fq, parse_decimal_fr, parse_hex20};
use crate::zkp::poseidon3;

/// Claimable proven deposits for a pubkey: only deposits to addresses
/// registered under it, at indices at/after their registration boundary.
fn available_deposits(s: &State, pk_x: Fr) -> U256 {
    let mut total = U256::ZERO;
    for (addr, ds) in &s.deposits {
        let Some(pk) = s.pubkey_by_addr.get(addr) else {
            continue;
        };
        if pk.into_affine().x != pk_x {
            continue;
        }
        let from = s.registered_from.get(addr).copied().unwrap_or(u64::MAX);
        for &(_, value, idx) in ds {
            if idx as u64 >= from {
                total += fr_to_u256(value);
            }
        }
    }
    total
}

pub fn spawn_http_server(app: AppState, listener: tokio::net::TcpListener) {
    tokio::spawn(async move {
        let router = Router::new()
            .route("/health", get(health))
            .route("/recipient", get(current_recipient))
            .route("/register", post(register))
            .route("/deposits/:pubkey_x", get(deposits))
            .route("/deposits-by-user-id/:user_id", get(deposits_by_user_id))
            .route("/balance/:pubkey_x", get(balance))
            .route("/cards", post(order_card))
            .route("/cards/:pubkey_x", get(card_orders))
            .route("/cards/:pubkey_x/:provider_ref/details", get(card_details))
            .route("/next_card_nonce/:pubkey_x", get(next_card_nonce))
            .route("/withdraw", post(request_withdraw))
            .route("/withdraws/:pubkey_x", get(withdraw_history))
            .route("/next_withdraw_nonce/:pubkey_x", get(next_withdraw_nonce))
            .route("/status", get(status))
            .with_state(app);
        axum::serve(listener, router).await.unwrap();
    });
}

async fn next_card_nonce(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    match app.db.next_card_nonce(pk_x).await {
        Ok(n) => Json(serde_json::json!({ "nonce": n })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ---- HTTP handlers ----

async fn health() -> &'static str {
    "ok"
}

async fn current_recipient(AxumState(app): AxumState<AppState>) -> impl IntoResponse {
    let s = app.state.lock().unwrap();
    let r = recipient(s.chain_id, s.exchange_addr, s.tweak);
    Json(serde_json::json!({ "recipient": r.to_string() })).into_response()
}

#[derive(serde::Deserialize)]
struct RegisterReq {
    address: String,          // 0x + 40 hex
    pubkey: (String, String), // P = (x, y), decimal, grumpkin base field
    sig_r: (String, String),  // R = (x, y), decimal
    sig_z: String,            // z = k + e·x, decimal, grumpkin scalar field
    salt: String,             // burn preimage nonce, decimal
}

async fn register(
    AxumState(app): AxumState<AppState>,
    Json(req): Json<RegisterReq>,
) -> impl IntoResponse {
    match register_inner(&app, req).await {
        Ok(()) => (StatusCode::OK, "registered").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn register_inner(app: &AppState, req: RegisterReq) -> Result<(), String> {
    let addr = parse_hex20(&req.address)?;
    let pk = G2Affine::new_unchecked(
        parse_decimal_fr(&req.pubkey.0)?,
        parse_decimal_fr(&req.pubkey.1)?,
    );
    let r = G2Affine::new_unchecked(
        parse_decimal_fr(&req.sig_r.0)?,
        parse_decimal_fr(&req.sig_r.1)?,
    );
    if !pk.is_on_curve() || !r.is_on_curve() {
        return Err("point not on curve".into());
    }
    use ark_ec::short_weierstrass::SWCurveConfig; // for GrumpkinConfig::GENERATOR
    if pk.is_zero() || pk.x == ark_grumpkin::GrumpkinConfig::GENERATOR.x {
        return Err("degenerate pubkey".into());
    }

    let z = parse_decimal_fq(&req.sig_z)?;
    let salt = parse_decimal_fr(&req.salt)?;

    let (recipient, registered_from, max_users) = {
        let s = app.state.lock().unwrap();
        (
            recipient(s.chain_id, s.exchange_addr, s.tweak),
            s.chain.index(),
            s.max_users,
        )
    };

    // Address must be derivable from (pubkey, salt) under the current recipient.
    let derived = trim_to_160(poseidon3(recipient, pk.x, salt).map_err(|e| e.to_string())?);
    if derived != addr {
        return Err("address does not match (pubkey, salt) for current recipient".into());
    }

    // Schnorr: z·G == R + e·P with e = poseidon3(R.x, P.x, recipient).
    let e_fr = poseidon3(r.x, pk.x, recipient).map_err(|e| e.to_string())?;
    let e = Fq::from_be_bytes_mod_order(&e_fr.into_bigint().to_bytes_be());
    let lhs = (G2::generator() * z).into_affine();
    let rhs = (G2::from(r) + G2::from(pk) * e).into_affine();
    if lhs != rhs {
        return Err("bad signature".into());
    }

    // pubkey is admitted only while unique users < MAX_USERS.
    if app
        .db
        .latest_registration_by_pubkey(pk.x)
        .await
        .map_err(|e| e.to_string())?
        .is_none()
    {
        let users = app
            .db
            .unique_user_count()
            .await
            .map_err(|e| e.to_string())?;
        if users >= max_users {
            return Err(format!("user limit reached ({})", max_users));
        }
    }

    let rec = Registration {
        address: addr,
        created_at: unix_now(),
        pubkey_x: pk.x,
        pubkey_y: pk.y,
        sig_r_x: r.x,
        sig_r_y: r.y,
        sig_z: z,
        salt,
        recipient,
        registered_from: registered_from as i64,
        user_id: crate::ids::user_id(pk.x),
    };
    app.db
        .insert_registration(&rec)
        .await
        .map_err(|e| e.to_string())?;

    let mut s = app.state.lock().unwrap();
    s.pubkey_by_addr.insert(addr, G2::from(pk));
    s.sig_by_addr.insert(addr, (G2::from(r), z));
    s.salt_by_addr.insert(addr, salt);
    s.registered_from
        .entry(addr)
        .and_modify(|f| *f = (*f).min(registered_from))
        .or_insert(registered_from);
    s.recipient_by_addr.insert(addr, recipient);

    Ok(())
}

async fn balance(AxumState(app): AxumState<AppState>, Path(pk): Path<String>) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let deposited = {
        let s = app.state.lock().unwrap();
        let mut total = U256::ZERO;
        for (addr, sum) in &s.credits {
            if s.pubkey_by_addr.get(addr).map(|p| p.into_affine().x) == Some(pk_x) {
                total += *sum;
            }
        }
        total
    };
    match app.db.total_spent(pk_x).await {
        Ok(spent) => {
            let balance = deposited.saturating_sub(spent);
            Json(serde_json::json!({
                "pubkey_x": pk,
                "deposited": deposited.to_string(),
                "spent": spent.to_string(),
                "balance": balance.to_string(),
            }))
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct CardOrderReq {
    pubkey_x: String, // decimal
    amount: String,   // decimal token units
    sig_r: (String, String),
    sig_z: String,
    nonce: i64,
}

async fn order_card(
    AxumState(app): AxumState<AppState>,
    Json(req): Json<CardOrderReq>,
) -> impl IntoResponse {
    match order_card_inner(&app, req).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn order_card_inner(app: &AppState, req: CardOrderReq) -> Result<serde_json::Value, String> {
    let pk_x = parse_decimal_fr(&req.pubkey_x)?;
    let amount = parse_decimal_fr(&req.amount)?;
    let r = G2Affine::new_unchecked(
        parse_decimal_fr(&req.sig_r.0)?,
        parse_decimal_fr(&req.sig_r.1)?,
    );
    if !r.is_on_curve() {
        return Err("sig_r not on curve".into());
    }
    let z = parse_decimal_fq(&req.sig_z)?;

    let reg = app
        .db
        .latest_registration_by_pubkey(pk_x)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "pubkey not registered".to_string())?;

    let (available, max_cards, window_days) = {
        let s = app.state.lock().unwrap();
        (
            available_deposits(&s, pk_x),
            s.max_cards_per_user,
            s.card_limit_window_days,
        )
    };

    let amount_u256 = fr_to_u256(amount);

    // 1. verify sig + reserve funds atomically (status 'pending')
    let provider_ref = format!("laso-{amount_u256}-{}", unix_now());
    let new_spent = app
        .db
        .try_card_order(
            reg.pubkey_x,
            reg.pubkey_y,
            amount,
            req.nonce,
            available,
            r,
            z,
            "laso",
            &provider_ref,
            max_cards,
            window_days,
        )
        .await?;

    // 2. provider call: x402-paid order from the operator wallet (mock or real,
    //    same protocol — LASO_URL decides which).
    match app.laso.order_card(&wei_to_usd(amount_u256)).await {
        Ok(o) => {
            app.db
                .settle_card_order(
                    &provider_ref,
                    "succeeded",
                    None,
                    Some((&o.card_id, &o.auth.id_token, &o.auth.refresh_token)),
                )
                .await?;
            Ok(serde_json::json!({
                "amount": amount_u256.to_string(),
                "provider": "laso",
                "provider_ref": provider_ref,
                "lifetime_spent": new_spent.to_string(),
            }))
        }
        Err(e) => {
            app.db
                .settle_card_order(&provider_ref, "failed", Some(&e), None)
                .await?;
            Err(format!("card provider failed: {e}"))
        }
    }
}

/// Latest status per card order for a pubkey — History's "Card load" rows.
async fn card_orders(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    match app.db.card_orders(pk_x).await {
        Ok(orders) => Json(serde_json::json!({
            "orders": orders
                .iter()
                .map(|o| serde_json::json!({
                    "provider_ref": o.provider_ref,
                    "amount": o.amount.to_string(),
                    "status": o.status,
                    "created_at": o.created_at,
                }))
                .collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Card details, proxied from Laso. Issue takes ~7-10s — callers poll every
/// 2-3s until `status` is "ready". 404 = stub-era order (pre-LASO_URL).
async fn card_details(
    AxumState(app): AxumState<AppState>,
    Path((pk, provider_ref)): Path<(String, String)>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let link = match app.db.card_link(pk_x, &provider_ref).await {
        Ok(Some(l)) => l,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown order").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if link.status == "failed" {
        return (StatusCode::NOT_FOUND, "order failed").into_response();
    }
    let (Some(card_id), Some(id_token), Some(refresh_token)) =
        (link.card_id, link.id_token, link.refresh_token)
    else {
        // Reservation in flight or order predates the provider integration.
        return Json(serde_json::json!({ "status": "pending" })).into_response();
    };
    match laso_card_data(&app, &provider_ref, &card_id, &id_token, &refresh_token).await {
        Ok(data) => Json(data).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

/// /get-card-data with one 401-retry: refresh_token first, full SIWX sign-in
/// as fallback. New tokens are appended to card_orders (latest row wins).
async fn laso_card_data(
    app: &AppState,
    provider_ref: &str,
    card_id: &str,
    id_token: &str,
    refresh_token: &str,
) -> Result<serde_json::Value, String> {
    let (status, body) = app.laso.card_data(id_token, card_id).await?;
    if status == 401 {
        let auth = match app.laso.refresh(refresh_token).await {
            Ok(a) => a,
            Err(_) => app.laso.auth().await?,
        };
        app.db
            .refresh_card_tokens(provider_ref, &auth.id_token, &auth.refresh_token)
            .await?;
        let (status, body) = app.laso.card_data(&auth.id_token, card_id).await?;
        if status != 200 {
            return Err(format!("laso /get-card-data {status}: {body}"));
        }
        return Ok(body);
    }
    if status != 200 {
        return Err(format!("laso /get-card-data {status}: {body}"));
    }
    Ok(body)
}

#[derive(serde::Deserialize)]
struct WithdrawReq {
    pubkey_x: String,    // decimal
    amount: String,      // decimal token units
    destination: String, // 0x + 40 hex
    nonce: i64,          // per-user sequence; signs over it, single-use
    sig_r: (String, String),
    sig_z: String,
}

async fn next_withdraw_nonce(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    match app.db.next_withdraw_nonce(pk_x).await {
        Ok(n) => Json(serde_json::json!({ "nonce": n })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn request_withdraw(
    AxumState(app): AxumState<AppState>,
    Json(req): Json<WithdrawReq>,
) -> impl IntoResponse {
    match withdraw_inner(&app, req).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

async fn withdraw_inner(app: &AppState, req: WithdrawReq) -> Result<serde_json::Value, String> {
    let pk_x = parse_decimal_fr(&req.pubkey_x)?;
    let amount = parse_decimal_fr(&req.amount)?;
    let destination = parse_hex20(&req.destination)?;
    let r = G2Affine::new_unchecked(
        parse_decimal_fr(&req.sig_r.0)?,
        parse_decimal_fr(&req.sig_r.1)?,
    );
    if !r.is_on_curve() {
        return Err("sig_r not on curve".into());
    }
    let z = parse_decimal_fq(&req.sig_z)?;

    let reg = app
        .db
        .latest_registration_by_pubkey(pk_x)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "pubkey not registered".to_string())?;

    let available = {
        let s = app.state.lock().unwrap();
        available_deposits(&s, pk_x)
    };

    let amount_u256 = fr_to_u256(amount);

    // Verify sig + reserve atomically (status 'pending'); the worker pays out.
    let ref_ = format!("wd-{amount_u256}-{}", unix_now());
    app.db
        .try_withdraw(
            reg.pubkey_x,
            reg.pubkey_y,
            amount,
            req.nonce,
            available,
            destination,
            r,
            z,
            &ref_,
        )
        .await?;

    Ok(serde_json::json!({
        "ref": ref_,
        "amount": amount_u256.to_string(),
        "status": "pending",
    }))
}

/// Latest status per withdraw request for a pubkey — History's "Withdraw" rows.
async fn withdraw_history(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    match app.db.withdraw_history(pk_x).await {
        Ok(rows) => Json(serde_json::json!({
            "withdraws": rows
                .iter()
                .map(|w| serde_json::json!({
                    "ref": w.ref_,
                    "amount": w.amount.to_string(),
                    "destination": format!("0x{}", hex::encode(w.destination)),
                    "status": w.status,
                    "created_at": w.created_at,
                }))
                .collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn status(AxumState(app): AxumState<AppState>) -> impl IntoResponse {
    let s = app.state.lock().unwrap();
    Json(serde_json::json!({
        "index": s.chain.index(),
        "root": s.tree.root().to_string(),
        "deposits": s.deposits.len(),
        "registered": s.pubkey_by_addr.len(),
    }))
    .into_response()
}

/// Claimable deposits (tree index >= registration boundary) for every address
/// whose registered pubkey is `pk_x`.
fn deposit_rows(s: &State, pk_x: Fr) -> Vec<serde_json::Value> {
    s.deposits
        .iter()
        .filter(|(addr, _)| s.pubkey_by_addr.get(*addr).map(|p| p.into_affine().x) == Some(pk_x))
        .flat_map(|(addr, ds)| {
            let from = s.registered_from.get(addr).copied().unwrap_or(u64::MAX);
            ds.iter().filter_map(move |(_, value, idx)| {
                (*idx as u64 >= from).then(|| {
                    serde_json::json!({
                        "address": format!("0x{}", hex::encode(addr)),
                        "value": value.to_string(),
                        "tree_index": idx,
                    })
                })
            })
        })
        .collect()
}

async fn deposits(
    AxumState(app): AxumState<AppState>,
    Path(pk): Path<String>,
) -> impl IntoResponse {
    let pk_x = match parse_decimal_fr(&pk) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let s = app.state.lock().unwrap();
    Json(serde_json::json!({ "deposits": deposit_rows(&s, pk_x) })).into_response()
}

async fn deposits_by_user_id(
    AxumState(app): AxumState<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let pk_x = match app.db.pubkey_by_user_id(&user_id).await {
        Ok(Some(pk)) => pk,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown user id").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let s = app.state.lock().unwrap();
    Json(serde_json::json!({ "deposits": deposit_rows(&s, pk_x) })).into_response()
}
