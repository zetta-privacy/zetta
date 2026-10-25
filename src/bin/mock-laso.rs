//! Mock Laso Finance API for development — mirrors https://docs.laso.finance
//! (openapi.json @ cd53dcba8fc8). In-memory only; restart wipes everything.
//!
//! Emulated faithfully:
//!   - x402 handshake: call without payment -> 402 {} + base64 PAYMENT-REQUIRED
//!     header (Base + Solana accepts, exact price in USDC atomic units); replay
//!     with PAYMENT-SIGNATURE / X-PAYMENT -> processed; wrong value -> second 402
//!     in the settlement-failure shape.
//!   - Auth: GET /auth (SIGN-IN-WITH-X), POST /auth refresh; paid routes return
//!     fresh `auth` credentials; Bearer required on read routes.
//!   - US cards: pending -> ready after MOCK_LASO_READY_MS (default 8s),
//!     card_details with billing_address(required=false), refresh-card-data
//!     with per-card 429s (1/5min, 12/24h).
//!   - Intl cards: whole dollars, +3.8% fee, queued -> complete after
//!     MOCK_LASO_INTL_READY_MS (default 15s); cancel-intl-order credits balance.
//!   - push-to-card (+4.8%, min 1.50, EUR/GBP fx), gift cards (+4.8%),
//!     account balance, withdraw (Solana, 202 + status_url), RateLimit-* headers.
//!
//! Not emulated: on-chain verification (presence + amount of the payment header
//! is enough), token expiry, Idempotency-Key, MPP, signup/banking routes.
//!
//! Run: `cargo run --bin mock-laso`
//! Env: MOCK_LASO_PORT (4100) · MOCK_LASO_BASE_URL · MOCK_LASO_READY_MS (8000)
//!      MOCK_LASO_INTL_READY_MS (15000) · MOCK_LASO_FROZEN=1 (403s everywhere)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State as AxumState};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Map, Value, json};

const DEFAULT_PORT: u16 = 4100;
const DOCS_VERSION: &str = "mocklaso0001";
const DEV_WALLET: &str = "0x0000000000000000000000000000000000000001";
const BASE_PAY_TO: &str = "0x3291e96b3bff7ed56e3ca8364273c5b4654b2b37";
const SOL_PAY_TO: &str = "3MZVk97x9SeRxbYpc3jhzRfU2fyA3emYutnqfn9kNfYX";
const USDC_BASE: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const USDC_SOL: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const WITHDRAW_AFTER_MS: u64 = 10_000;

// ---------- app ----------

#[derive(Clone)]
struct App {
    store: Arc<Mutex<Store>>,
    base_url: String,
    ready_ms: u64,
    intl_ready_ms: u64,
}

#[derive(Default)]
struct Store {
    accounts: HashMap<String, Account>,
    id_tokens: HashMap<String, String>,      // id_token -> user_id
    refresh_tokens: HashMap<String, String>, // refresh_token -> user_id
    cards: HashMap<String, Card>,
    withdrawals: HashMap<String, Withdrawal>,
    seq: u64,
}

struct Account {
    balance: f64,
    total_deposits: f64,
    created_ms: u64,
}

impl Store {
    fn account(&mut self, user: &str) -> &mut Account {
        self.accounts.entry(user.into()).or_insert_with(|| Account {
            balance: 0.0,
            total_deposits: 0.0,
            created_ms: now_ms(),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Us,
    Intl,
}

impl Kind {
    fn type_str(self) -> &'static str {
        match self {
            Kind::Us => "Non-Reloadable U.S.",
            Kind::Intl => "Non-Reloadable International",
        }
    }
}

struct Card {
    card_id: String,
    user_id: String,
    kind: Kind,
    usd_amount: f64,
    created_ms: u64,
    ready_at_ms: u64,
    available_balance: f64,
    charged_usd_amount: Option<f64>, // intl only
    fees_paid: Option<f64>,          // intl only
    refunded: bool,                  // intl only (cancel-intl-order)
    pan: String,
    cvv: String,
    exp_month: String,
    exp_year: String,
    refresh_ts: Vec<u64>, // refresh-card-data calls (rate-limit window)
    last_updated_ms: u64,
}

impl Card {
    /// CardData, with status computed relative to `now`.
    fn json(&self, now: u64) -> Value {
        let intl = self.kind == Kind::Intl;
        let status = if intl {
            if self.refunded {
                "refunded"
            } else if now >= self.ready_at_ms {
                "complete"
            } else {
                "queued"
            }
        } else if now >= self.ready_at_ms {
            "ready"
        } else {
            "pending"
        };
        let mut v = json!({
            "card_id": self.card_id,
            "card_type": self.kind.type_str(),
            "usd_amount": self.usd_amount,
            "timestamp": self.created_ms,
            "timestamp_readable": readable(self.created_ms),
            "status": status,
            "transactions": [],
        });
        if intl {
            v["label"] = json!(null);
            v["charged_usd_amount"] = json!(self.charged_usd_amount);
            v["fees_paid"] = json!(self.fees_paid);
            v["state"] = json!(status); // queued | complete | refunded
            v["balance_update_requested_timestamp"] = json!(null);
            // Mock keeps a stable card_id across fulfillment.
            v["queued_order_card_id"] = json!(null);
        } else {
            v["country"] = json!("US");
            v["last_updated_timestamp"] = json!(self.last_updated_ms);
        }
        if status == "ready" || status == "complete" {
            v["card_details"] = json!({
                "card_number": self.pan,
                "exp_month": self.exp_month,
                "exp_year": self.exp_year,
                "cvv": self.cvv,
                "available_balance": self.available_balance,
                "billing_address": {
                    "name": "Laso Finance",
                    "line_1": "123 Main Street",
                    "line_2": "",
                    "city": "San Francisco",
                    "state": "CA",
                    "zip": "94105",
                    "country": "US",
                    "required": intl,
                    "note": if intl {
                        "Merchant AVS is validated against exactly this address."
                    } else {
                        "Any valid U.S. billing address works; this is a known-good default."
                    },
                },
            });
        }
        v
    }
}

struct Withdrawal {
    id: String,
    user_id: String,
    amount: f64,
    solana_address: String,
    created_ms: u64,
    completes_at_ms: u64,
    tx_hash: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    dotenv::dotenv().ok();

    let port: u16 = std::env::var("MOCK_LASO_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let app = App {
        store: Arc::new(Mutex::new(Store::default())),
        base_url: std::env::var("MOCK_LASO_BASE_URL")
            .unwrap_or_else(|_| format!("http://0.0.0.0:{port}")),
        ready_ms: env_u64("MOCK_LASO_READY_MS", 8_000),
        intl_ready_ms: env_u64("MOCK_LASO_INTL_READY_MS", 15_000),
    };

    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/auth", get(auth_get).post(auth_refresh))
        .route("/get-card", get(get_card))
        .route("/get-card-data", get(get_card_data))
        .route("/refresh-card-data", post(refresh_card_data))
        .route("/order-intl-card", get(order_intl_card))
        .route("/cancel-intl-order", post(cancel_intl_order))
        .route("/get-push-to-card", get(get_push_to_card))
        .route("/search-gift-cards", get(search_gift_cards))
        .route("/order-gift-card", get(order_gift_card))
        .route("/get-account-balance", get(get_account_balance))
        .route("/withdraw", post(withdraw))
        .route("/get-withdrawal-status", get(get_withdrawal_status))
        .route("/redeem/:id", get(redeem))
        .layer(middleware::from_fn(add_headers))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "mock laso api listening");
    axum::serve(listener, router).await?;
    Ok(())
}

// ---------- free routes ----------

async fn health() -> &'static str {
    "ok"
}

async fn version(AxumState(app): AxumState<App>) -> impl IntoResponse {
    Json(json!({
        "docs_version": DOCS_VERSION,
        "docs_manifest_url": format!("{}/.well-known/docs-version.json", app.base_url),
        "api_catalog_url": format!("{}/.well-known/api-catalog", app.base_url),
        "docs": null,
        "note": "Mock Laso server for development — mirrors docs revision cd53dcba8fc8.",
    }))
}

async fn auth_get(AxumState(app): AxumState<App>, headers: HeaderMap) -> Response {
    let Some(siwx) = headers.get("sign-in-with-x").and_then(|v| v.to_str().ok()) else {
        // Per spec, SIWX failures also answer 402 with a fresh challenge.
        let challenge = json!({
            "x402Version": 2,
            "accepts": [],
            "siwx": {
                "domain": app.base_url,
                "statement": "Sign in to Laso Finance",
                "nonce": format!("mocknonce{}", now_ms()),
            },
        });
        return challenge_response_raw(&challenge);
    };
    let user = b64_decode(siwx)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| extract_evm_address(&t))
        .unwrap_or_else(|| DEV_WALLET.into());
    let mut s = app.store.lock().unwrap();
    s.account(&user);
    Json(envelope(&app, &mut s, &user, vec![])).into_response()
}

async fn auth_refresh(AxumState(app): AxumState<App>, Json(body): Json<Value>) -> Response {
    if body["grant_type"].as_str() != Some("refresh_token") {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": "Invalid or missing grant_type. Must be \"refresh_token\" for POST /auth."}),
        );
    }
    let Some(rt) = body["refresh_token"].as_str() else {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": "Invalid or missing grant_type. Must be \"refresh_token\" for POST /auth."}),
        );
    };
    let mut s = app.store.lock().unwrap();
    let Some(user) = s.refresh_tokens.get(rt).cloned() else {
        return err(
            StatusCode::UNAUTHORIZED,
            json!({"error": "Failed to refresh token. Token may be invalid or revoked."}),
        );
    };
    let auth = mint_auth(&mut s, &user);
    Json(json!({
        "id_token": auth["id_token"],
        "refresh_token": auth["refresh_token"],
        "expires_in": auth["expires_in"],
        "user_id": user,
    }))
    .into_response()
}

// ---------- paid (x402) routes ----------

async fn get_card(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let amount = match usd_param(&q, 5.0, 1_000.0) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let url = format!("{}/get-card?amount={}", app.base_url, q["amount"]);
    let payer = match check_payment(&headers, &url, amount) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }

    let now = now_ms();
    let mut s = app.store.lock().unwrap();
    s.account(&payer);
    let card = new_card(
        &mut s,
        &payer,
        Kind::Us,
        amount,
        now,
        now + app.ready_ms,
        None,
    );
    let payload = json!({
        "card_id": card.card_id,
        "usd_amount": card.usd_amount,
        "country": "US",
        "timestamp": card.created_ms,
        "timestamp_readable": readable(card.created_ms),
        "status": "pending",
    });
    tracing::info!(user = %payer, amount, "card ordered");
    s.cards.insert(card.card_id.clone(), card);
    Json(envelope(&app, &mut s, &payer, vec![("card", payload)])).into_response()
}

async fn order_intl_card(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let amount = match q.get("amount").and_then(|v| v.parse::<f64>().ok()) {
        Some(a) if (100.0..=1_000.0).contains(&a) => a,
        Some(a) => {
            let bound = if a < 100.0 {
                "at least $100"
            } else {
                "at most $1000"
            };
            return err(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("Amount must be {bound}. Received: {}", fmt_usd(a))}),
            );
        }
        None => {
            return err(
                StatusCode::BAD_REQUEST,
                json!({"error": "Invalid or missing amount"}),
            );
        }
    };
    if amount.fract() != 0.0 {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": format!("Amount must be a whole dollar amount. Received: {}", fmt_usd(amount))}),
        );
    }

    let fee = round2(amount * 0.038);
    let charged = round2(amount + fee);
    let url = format!("{}/order-intl-card?amount={}", app.base_url, q["amount"]);
    let payer = match check_payment(&headers, &url, charged) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }

    let now = now_ms();
    let mut s = app.store.lock().unwrap();
    s.account(&payer);
    let card = new_card(
        &mut s,
        &payer,
        Kind::Intl,
        amount,
        now,
        now + app.intl_ready_ms,
        Some((charged, fee)),
    );
    let payload = json!({
        "on_card_usd_amount": amount,
        "charged_usd_amount": charged,
        "status": "queued",
        "timestamp": now,
        "card_id": card.card_id,
    });
    let id = card.card_id.clone();
    tracing::info!(user = %payer, amount, charged, "intl card queued");
    s.cards.insert(id.clone(), card);
    Json(envelope(&app, &mut s, &payer, vec![
        ("intl_card_order", payload),
        ("message", json!(format!(
            "International card order {id} queued. Mock fulfills after {}s; poll /get-card-data?card_id={id}.",
            app.intl_ready_ms / 1000
        ))),
    ]))
    .into_response()
}

async fn get_push_to_card(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let currency = q.get("currency").map(String::as_str).unwrap_or("USD");
    let (fx, note) = match currency {
        "USD" => (1.0, "USD: U.S. debit cards (U.S. bank accounts) only."),
        "EUR" => (1.08, "EUR: Eurozone debit cards only."),
        "GBP" => (1.27, "GBP: U.K. debit cards only."),
        other => {
            return err(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("currency must be USD, EUR, or GBP. Received: {other}")}),
            );
        }
    };
    let amount = match q.get("amount").and_then(|v| v.parse::<f64>().ok()) {
        Some(a) if (10.0..=9_541.98).contains(&a) => a,
        Some(a) => {
            return err(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("Amount must be between 10 and 9,541.98. Received: {}", fmt_usd(a))}),
            );
        }
        None => {
            return err(
                StatusCode::BAD_REQUEST,
                json!({"error": "Invalid or missing amount"}),
            );
        }
    };

    let fee = round2((amount * 0.048).max(1.50));
    let price = round2((amount + fee) * fx);
    let url = format!(
        "{}/get-push-to-card?amount={}&currency={currency}",
        app.base_url, q["amount"]
    );
    let payer = match check_payment(&headers, &url, price) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }

    let mut s = app.store.lock().unwrap();
    s.account(&payer);
    s.seq += 1;
    let id = format!("ptc_{}", s.seq);
    tracing::info!(user = %payer, amount, currency, price, "push-to-card initiated");
    Json(envelope(&app, &mut s, &payer, vec![
        ("success", json!(true)),
        ("message", json!("Push-to-card transfer initiated. Open the redemption_url to enter your debit card details and complete the transfer.")),
        ("amount", json!(amount)),
        ("currency", json!(currency)),
        ("redemption_url", json!(format!("{}/redeem/{id}", app.base_url))),
        ("note", json!(format!("{note} The form requires: sender name, debit card number, and cardholder name."))),
    ]))
    .into_response()
}

async fn order_gift_card(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(id) = q.get("laso_server_id") else {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": "laso_server_id query parameter is required"}),
        );
    };
    let Some(product) = GIFT_CATALOG.iter().find(|p| p.laso_server_id == id) else {
        // Terminal 404, returned before a payment is ever quoted.
        return err(
            StatusCode::NOT_FOUND,
            json!({
                "error": format!("No gift card in the catalog has laso_server_id \"{id}\"."),
                "code": "unknown_laso_server_id",
                "terminal": true,
                "laso_server_id": id,
                "hint": "Find a valid laso_server_id with GET /search-gift-cards and order with that value. No payment was taken for this request.",
                "search_url": format!("{}/search-gift-cards", app.base_url),
            }),
        );
    };
    let country = q.get("country").map(String::as_str).unwrap_or("US");
    let amount = match q.get("amount").and_then(|v| v.parse::<f64>().ok()) {
        Some(a) if a > 0.0 => a,
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                json!({"error": "amount query parameter is required and must be positive"}),
            );
        }
    };
    let usd = round2(amount * product.fx);
    if !(5.0..=9_000.0).contains(&usd) {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": format!("Converted amount must be between $5 and $9,000. {} {amount} = {}", product.currency, fmt_usd(usd))}),
        );
    }

    let fee = round2(usd * 0.048);
    let price = round2(usd + fee);
    let url = format!(
        "{}/order-gift-card?amount={}&laso_server_id={id}&country={country}",
        app.base_url, q["amount"]
    );
    let payer = match check_payment(&headers, &url, price) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }

    let now = now_ms();
    let mut s = app.store.lock().unwrap();
    s.account(&payer);
    s.seq += 1;
    let n = s.seq;
    tracing::info!(user = %payer, id, amount, usd, price, "gift card ordered");
    let gift_card = json!({
        "card_id": format!("gc_{n:06}"),
        "laso_server_id": id,
        "amount": amount,
        "currency": product.currency,
        "country": country,
        "redemption_url": format!("{}/redeem/gc_{n:06}", app.base_url),
        "redemption_code": format!("MOCK-{n:04X}-GIFT"),
        "pin_code": format!("{:04}", n % 10_000),
        "status": "completed",
        "timestamp": now,
    });
    Json(envelope(
        &app,
        &mut s,
        &payer,
        vec![("gift_card", gift_card)],
    ))
    .into_response()
}

// ---------- authenticated routes ----------

async fn get_card_data(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let user = match bearer(&app, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }
    let card_type = q
        .get("card_type")
        .map(String::as_str)
        .unwrap_or(Kind::Us.type_str());
    if ![
        "Non-Reloadable U.S.",
        "Non-Reloadable International",
        "Reloadable",
    ]
    .contains(&card_type)
    {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": format!("card_type must be \"Non-Reloadable U.S.\", \"Non-Reloadable International\" or \"Reloadable\". Received: {card_type}")}),
        );
    }

    let now = now_ms();
    let s = app.store.lock().unwrap();
    if let Some(id) = q.get("card_id") {
        let Some(card) = s.cards.get(id) else {
            return err(StatusCode::NOT_FOUND, json!({"error": "Card not found"}));
        };
        if card.user_id != user {
            return err(
                StatusCode::FORBIDDEN,
                json!({"error": "Not authorized to view this card"}),
            );
        }
        return Json(card.json(now)).into_response();
    }

    let mut cards: Vec<Value> = s
        .cards
        .values()
        .filter(|c| c.user_id == user && c.kind.type_str() == card_type)
        .map(|c| c.json(now))
        .collect();
    cards.sort_by_key(|c| c["timestamp"].as_u64().unwrap_or(0));
    cards.reverse();
    Json(json!({ "cards": cards })).into_response()
}

async fn refresh_card_data(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let user = match bearer(&app, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }
    let Some(id) = body["card_id"].as_str() else {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": "card_id is required in request body"}),
        );
    };

    let now = now_ms();
    let mut s = app.store.lock().unwrap();
    let Some(card) = s.cards.get_mut(id).filter(|c| c.user_id == user) else {
        return err(StatusCode::NOT_FOUND, json!({"error": "Card not found"}));
    };

    // Per-card limits: one refresh per 5 minutes, 12 per rolling 24 hours.
    if let Some(&last) = card.refresh_ts.last() {
        if now < last + 300_000 {
            let wait = (last + 300_000 - now) / 1000 + 1;
            return rate_limited(
                wait,
                "Card data was refreshed recently. Please wait before requesting another refresh.",
            );
        }
    }
    card.refresh_ts
        .retain(|&t| t > now.saturating_sub(86_400_000));
    if card.refresh_ts.len() >= 12 {
        let wait = (card.refresh_ts[0] + 86_400_000 - now) / 1000 + 1;
        return rate_limited(
            wait,
            "Daily card refresh limit reached. You can request at most 12 refreshes for a card in a 24-hour period.",
        );
    }
    card.refresh_ts.push(now);
    card.last_updated_ms = now;
    Json(json!({ "success": true, "message": "Card refresh requested." })).into_response()
}

async fn cancel_intl_order(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let user = match bearer(&app, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }
    let Some(id) = body["card_id"].as_str() else {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": "card_id is required in request body"}),
        );
    };

    let now = now_ms();
    let mut s = app.store.lock().unwrap();
    let Some(card) = s.cards.get_mut(id).filter(|c| c.user_id == user) else {
        return err(StatusCode::NOT_FOUND, json!({"error": "Card not found"}));
    };
    if card.kind != Kind::Intl || now >= card.ready_at_ms {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": "Card is not in a queued state"}),
        );
    }
    card.refunded = true;
    let charged = card.charged_usd_amount.unwrap_or(0.0);
    let acc = s.account(&user);
    acc.balance = round2(acc.balance + charged);
    acc.total_deposits = round2(acc.total_deposits + charged);
    Json(json!({
        "card_id": id,
        "message": format!("Order cancelled and {} credited to your account balance.", fmt_usd(charged)),
    }))
    .into_response()
}

async fn get_account_balance(AxumState(app): AxumState<App>, headers: HeaderMap) -> Response {
    let user = match bearer(&app, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }
    let mut s = app.store.lock().unwrap();
    let acc = s.account(&user);
    Json(json!({
        "user_id": user,
        "balance": acc.balance,
        "total_deposits": acc.total_deposits,
        "created_timestamp": acc.created_ms,
        "created_timestamp_readable": readable(acc.created_ms),
    }))
    .into_response()
}

async fn withdraw(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let user = match bearer(&app, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }
    let amount = match body["amount"].as_f64() {
        Some(a) if a >= 0.01 => round2(a),
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                json!({"error": "Invalid or missing amount"}),
            );
        }
    };
    let Some(addr) = body["solana_address"].as_str() else {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": "solana_address is required", "code": "invalid_solana_address"}),
        );
    };
    if !is_solana_address(addr) {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": format!("solana_address is not a valid Solana address. Received: {addr}"), "code": "invalid_solana_address"}),
        );
    }

    let now = now_ms();
    let mut s = app.store.lock().unwrap();
    let acc = s.account(&user);
    if acc.balance < amount {
        return err(
            StatusCode::BAD_REQUEST,
            json!({"error": format!("Insufficient funds. Current balance: {}", fmt_usd(acc.balance))}),
        );
    }
    acc.balance = round2(acc.balance - amount);
    s.seq += 1;
    let id = format!("wd_{}", s.seq);
    let wd = Withdrawal {
        id: id.clone(),
        user_id: user.clone(),
        amount,
        solana_address: addr.into(),
        created_ms: now,
        completes_at_ms: now + WITHDRAW_AFTER_MS,
        tx_hash: mock_tx_hash(&id),
    };
    s.withdrawals.insert(wd.id.clone(), wd);
    let status_url = format!("{}/get-withdrawal-status?withdrawal_id={id}", app.base_url);
    tracing::info!(user = %user, amount, "withdrawal created");
    (
        StatusCode::ACCEPTED,
        [(axum::http::header::LOCATION, status_url.clone())],
        Json(json!({
            "success": true,
            "status_url": status_url,
            "withdrawal": {
                "id": id,
                "amount": amount,
                "state": "pending",
                "solana_address": addr,
                "timestamp": now,
                "timestamp_readable": readable(now),
            },
        })),
    )
        .into_response()
}

async fn get_withdrawal_status(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let user = match bearer(&app, &headers) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if frozen() {
        return frozen_err();
    }
    let now = now_ms();
    let s = app.store.lock().unwrap();
    let status_json = |w: &Withdrawal| {
        let completed = now >= w.completes_at_ms;
        let mut v = json!({
            "id": w.id,
            "amount": w.amount,
            "asset": "USDC",
            "network": "SOLANA_MAINNET",
            "state": if completed { "completed" } else { "pending" },
            "address": w.solana_address,
            "timestamp": w.created_ms,
            "timestamp_readable": readable(w.created_ms),
        });
        if completed {
            v["tx_hash"] = json!(w.tx_hash);
            v["tx_url"] = json!(format!("https://solscan.io/tx/{}", w.tx_hash));
        }
        v
    };
    if let Some(id) = q.get("withdrawal_id") {
        let Some(w) = s.withdrawals.get(id).filter(|w| w.user_id == user) else {
            return err(
                StatusCode::NOT_FOUND,
                json!({"error": "Withdrawal not found"}),
            );
        };
        return Json(json!({ "withdrawal": status_json(w) })).into_response();
    }
    let mut all: Vec<(&u64, Value)> = s
        .withdrawals
        .values()
        .filter(|w| w.user_id == user)
        .map(|w| (&w.created_ms, status_json(w)))
        .collect();
    all.sort_by_key(|(t, _)| **t);
    all.reverse();
    Json(json!({ "withdrawals": all.into_iter().map(|(_, v)| v).collect::<Vec<_>>() }))
        .into_response()
}

async fn search_gift_cards(
    AxumState(app): AxumState<App>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Err(r) = bearer(&app, &headers) {
        return r;
    }
    let matches = |p: &&GiftProduct| {
        q.get("q")
            .is_none_or(|v| p.name.to_lowercase().contains(&v.to_lowercase()))
            && q.get("country")
                .is_none_or(|v| p.country.is_none_or(|c| c == v))
            && q.get("currency").is_none_or(|v| p.currency == v)
            && q.get("category").is_none_or(|v| p.category == v)
    };
    let cards: Vec<Value> = GIFT_CATALOG.iter().filter(matches).map(gift_json).collect();

    let mut categories: Vec<&str> = GIFT_CATALOG.iter().map(|p| p.category).collect();
    let mut currencies: Vec<&str> = GIFT_CATALOG.iter().map(|p| p.currency).collect();
    let mut countries: Vec<&str> = GIFT_CATALOG.iter().filter_map(|p| p.country).collect();
    categories.sort_unstable();
    currencies.sort_unstable();
    countries.sort_unstable();
    categories.dedup();
    currencies.dedup();
    countries.dedup();

    Json(json!({
        "gift_cards": cards,
        "count": cards.len(),
        "filters": {
            "query": q.get("q"),
            "country": q.get("country"),
            "currency": q.get("currency"),
            "category": q.get("category"),
        },
        "facets": {
            "categories": categories,
            "currencies": currencies,
            "countries": countries,
        },
        "note": "Mock catalog — a small static subset of Laso's gift cards.",
    }))
    .into_response()
}

async fn redeem(Path(id): Path<String>) -> Html<String> {
    Html(format!(
        "<!doctype html><title>Mock Laso redeem</title>\
         <h1>{id}</h1>\
         <p>Mock redemption page. In production this form collects sender name, \
         debit card number, and cardholder name. No-op in development.</p>"
    ))
}

// ---------- x402 ----------

/// Ok(user_id) when a payment header is present and (for EVM) covers the price.
/// Err(402 challenge) when absent/undecodable; Err(402 settlement failure) when
/// the authorization value doesn't match the challenge amount.
fn check_payment(headers: &HeaderMap, url: &str, price_usd: f64) -> Result<String, Response> {
    let Some(hv) = headers
        .get("payment-signature")
        .or_else(|| headers.get("x-payment"))
    else {
        return Err(x402_challenge(url, price_usd));
    };
    let payment: Value = hv
        .to_str()
        .ok()
        .and_then(|s| b64_decode(s).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| x402_challenge(url, price_usd))?;

    let network = payment
        .pointer("/accepted/network")
        .or_else(|| payment.get("network"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let payer = payment
        .pointer("/payload/authorization/from")
        .and_then(Value::as_str)
        .map(str::to_lowercase)
        .unwrap_or_else(|| DEV_WALLET.into());

    if network.starts_with("eip155") {
        let expected = usd_atomic(price_usd).to_string();
        let got = payment
            .pointer("/payload/authorization/value")
            .and_then(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
            });
        if let Some(got) = got {
            if got != expected {
                return Err((
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({
                        "success": false,
                        "errorReason": "invalid_exact_evm_payload_authorization_value",
                        "errorMessage": format!(
                            "mock-laso: payment value {got} does not match the challenge amount {expected} ({})",
                            fmt_usd(price_usd)
                        ),
                        "x_laso_guidance": "Pay the fee-inclusive price from the 402 challenge, not the pre-fee amount."
                    })),
                )
                    .into_response());
            }
        }
    }
    Ok(payer)
}

fn x402_challenge(url: &str, price_usd: f64) -> Response {
    let atomic = usd_atomic(price_usd).to_string();
    let body = json!({
        "x402Version": 2,
        "error": "Payment required",
        "resource": { "url": url, "mimeType": "application/json" },
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": atomic,
                "asset": USDC_BASE,
                "payTo": BASE_PAY_TO,
                "maxTimeoutSeconds": 345600,
                "extra": { "name": "USD Coin", "version": "2", "assetTransferMethod": "eip3009" },
            },
            {
                "scheme": "exact",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "amount": atomic,
                "asset": USDC_SOL,
                "payTo": SOL_PAY_TO,
                "maxTimeoutSeconds": 345600,
                "extra": {},
            },
        ],
    });
    challenge_response_raw(&body)
}

fn challenge_response_raw(challenge: &Value) -> Response {
    let hv = HeaderValue::from_str(&b64_encode(challenge.to_string().as_bytes()))
        .unwrap_or_else(|_| HeaderValue::from_static(""));
    let mut res = (StatusCode::PAYMENT_REQUIRED, Json(json!({}))).into_response();
    res.headers_mut().insert("payment-required", hv);
    res
}

// ---------- helpers ----------

fn bearer(app: &App, headers: &HeaderMap) -> Result<String, Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Missing or invalid Authorization header"}),
            )
        })?;
    app.store
        .lock()
        .unwrap()
        .id_tokens
        .get(token)
        .cloned()
        .ok_or_else(|| {
            err(
                StatusCode::UNAUTHORIZED,
                json!({"error": "Invalid or expired token"}),
            )
        })
}

fn mint_auth(s: &mut Store, user_id: &str) -> Value {
    s.seq += 1;
    let id = format!("lasomock_id_{}", s.seq);
    let rt = format!("lasomock_rt_{}", s.seq);
    s.id_tokens.insert(id.clone(), user_id.into());
    s.refresh_tokens.insert(rt.clone(), user_id.into());
    json!({ "id_token": id, "refresh_token": rt, "expires_in": "3600" })
}

/// Shared paid-route response wrapper: { auth, callable_base_url, user_id, ...extra }.
fn envelope(app: &App, s: &mut Store, user_id: &str, extra: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    m.insert("auth".into(), mint_auth(s, user_id));
    m.insert("callable_base_url".into(), app.base_url.clone().into());
    m.insert("user_id".into(), user_id.into());
    for (k, v) in extra {
        m.insert(k.into(), v);
    }
    Value::Object(m)
}

fn new_card(
    s: &mut Store,
    user: &str,
    kind: Kind,
    usd_amount: f64,
    now: u64,
    ready_at: u64,
    economics: Option<(f64, f64)>,
) -> Card {
    s.seq += 1;
    let n = s.seq;
    let (y, m, _) = civil_from_days((now / 86_400_000) as i64);
    Card {
        card_id: format!("mockcard_{n:06}"),
        user_id: user.into(),
        kind,
        usd_amount,
        created_ms: now,
        ready_at_ms: ready_at,
        available_balance: usd_amount,
        charged_usd_amount: economics.map(|e| e.0),
        fees_paid: economics.map(|e| e.1),
        refunded: false,
        pan: pan_for(n),
        cvv: format!("{:03}", (n.wrapping_mul(7919) + 137) % 1000),
        exp_month: format!("{m:02}"),
        exp_year: format!("{}", y + 3),
        refresh_ts: vec![],
        last_updated_ms: now,
    }
}

fn usd_param(q: &HashMap<String, String>, min: f64, max: f64) -> Result<f64, Response> {
    match q.get("amount").and_then(|v| v.parse::<f64>().ok()) {
        Some(a) if (min..=max).contains(&a) => Ok(a),
        Some(a) => {
            let bound = if a < min {
                format!("at least {}", fmt_usd(min))
            } else {
                format!("at most {}", fmt_usd(max))
            };
            Err(err(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("Amount must be {bound}. Received: {}", fmt_usd(a))}),
            ))
        }
        None => Err(err(
            StatusCode::BAD_REQUEST,
            json!({"error": "Invalid or missing amount"}),
        )),
    }
}

fn rate_limited(wait: u64, msg: &str) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, wait.to_string())],
        Json(json!({
            "error": msg,
            "code": "rate_limited",
            "retry_after_seconds": wait,
            "hint": "This limit is per card: at most one refresh every 5 minutes, and 12 in any rolling 24-hour period.",
        })),
    )
        .into_response()
}

fn err(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn frozen() -> bool {
    std::env::var("MOCK_LASO_FROZEN").is_ok_and(|v| v == "1")
}

fn frozen_err() -> Response {
    err(
        StatusCode::FORBIDDEN,
        json!({
            "error": "Account is frozen",
            "frozen_message": "Your account is frozen pending a compliance review. Contact support@laso.finance. (mock: MOCK_LASO_FROZEN=1)",
        }),
    )
}

async fn add_headers(req: axum::http::Request<axum::body::Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("RateLimit-Limit", HeaderValue::from_static("120"));
    h.insert("RateLimit-Remaining", HeaderValue::from_static("118"));
    h.insert("RateLimit-Reset", HeaderValue::from_static("42"));
    h.insert("RateLimit-Policy", HeaderValue::from_static("120;w=60"));
    h.insert("X-RateLimit-Limit", HeaderValue::from_static("120"));
    h.insert("X-RateLimit-Remaining", HeaderValue::from_static("118"));
    h.insert("X-RateLimit-Reset", HeaderValue::from_static("42"));
    h.insert("X-RateLimit-Policy", HeaderValue::from_static("120;w=60"));
    h.insert(
        "X-Laso-Docs-Version",
        HeaderValue::from_static(DOCS_VERSION),
    );
    res
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn usd_atomic(usd: f64) -> u64 {
    (usd * 1e6).round() as u64
}

fn fmt_usd(x: f64) -> String {
    if x.fract() == 0.0 {
        format!("${x:.0}")
    } else {
        format!("${x:.2}")
    }
}

fn is_solana_address(s: &str) -> bool {
    (32..=44).contains(&s.len())
        && s.bytes()
            .all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
}

/// Mock transaction hash: FNV-1a of the id, repeated to 64 hex chars.
fn mock_tx_hash(id: &str) -> String {
    let f = |s: &str| {
        let mut h = 0xcbf29ce484222325u64;
        for b in s.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    };
    let (a, b) = (f(&format!("{id}a")), f(&format!("{id}b")));
    format!("{a:016x}{b:016x}{a:016x}{b:016x}")
}

fn extract_evm_address(text: &str) -> Option<String> {
    let b = text.as_bytes();
    for i in 0..b.len().saturating_sub(41) {
        if b[i] == b'0' && b[i + 1] == b'x' && b[i + 2..i + 42].iter().all(u8::is_ascii_hexdigit) {
            return Some(text[i..i + 42].to_lowercase());
        }
    }
    None
}

/// "9/14/2026, 6:47:34 AM" — matches Laso's timestamp_readable shape.
fn readable(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let day = secs % 86_400;
    let h24 = day / 3600;
    let (h12, ampm) = if h24 == 0 {
        (12, "AM")
    } else if h24 < 12 {
        (h24, "AM")
    } else if h24 == 12 {
        (12, "PM")
    } else {
        (h24 - 12, "PM")
    };
    format!(
        "{m}/{d}/{y}, {}:{:02}:{:02} {}",
        h12,
        (day % 3600) / 60,
        day % 60,
        ampm
    )
}

/// Civil (y, m, d) from days since epoch — Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Visa-style PAN: BIN 400000 + serial + Luhn check digit (16 digits).
fn pan_for(n: u64) -> String {
    let payload = format!("400000{n:09}");
    format!("{payload}{}", luhn_check_digit(&payload))
}

fn luhn_check_digit(payload: &str) -> u32 {
    let sum: u32 = payload
        .chars()
        .rev()
        .enumerate()
        .map(|(r, c)| {
            let d = c.to_digit(10).unwrap();
            if r % 2 == 0 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    (10 - sum % 10) % 10
}

// ---------- base64 (no extra deps) ----------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, ()> {
    let mut table = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut nbits) = (0u32, 0u32);
    for &byte in s.as_bytes() {
        let byte = match byte {
            b'-' => b'+', // tolerate base64url
            b'_' => b'/',
            other => other,
        };
        if byte == b'=' {
            break;
        }
        let v = table[byte as usize];
        if v == 255 {
            return Err(());
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

// ---------- gift card catalog (static subset) ----------

struct GiftProduct {
    laso_server_id: &'static str,
    name: &'static str,
    description: &'static str,
    category: &'static str,
    country: Option<&'static str>,
    currency: &'static str,
    min: f64,
    max: f64,
    fx: f64, // currency -> USD
}

const GIFT_CATALOG: &[GiftProduct] = &[
    GiftProduct {
        laso_server_id: "amazon",
        name: "Amazon",
        description: "Amazon.com gift card",
        category: "ecommerce",
        country: Some("US"),
        currency: "USD",
        min: 5.0,
        max: 2_000.0,
        fx: 1.0,
    },
    GiftProduct {
        laso_server_id: "uber",
        name: "Uber",
        description: "Uber rides and eats",
        category: "travel",
        country: Some("US"),
        currency: "USD",
        min: 5.0,
        max: 500.0,
        fx: 1.0,
    },
    GiftProduct {
        laso_server_id: "netflix",
        name: "Netflix",
        description: "Netflix subscription credit",
        category: "entertainment",
        country: Some("US"),
        currency: "USD",
        min: 10.0,
        max: 200.0,
        fx: 1.0,
    },
    GiftProduct {
        laso_server_id: "zalando",
        name: "Zalando",
        description: "Zalando fashion store",
        category: "ecommerce",
        country: Some("DE"),
        currency: "EUR",
        min: 5.0,
        max: 1_500.0,
        fx: 1.08,
    },
    GiftProduct {
        laso_server_id: "talabat",
        name: "Talabat",
        description: "Talabat food delivery",
        category: "food",
        country: Some("AE"),
        currency: "SAR",
        min: 20.0,
        max: 1_000.0,
        fx: 0.27,
    },
];

fn gift_json(p: &GiftProduct) -> Value {
    json!({
        "laso_server_id": p.laso_server_id,
        "name": p.name,
        "description": p.description,
        "category": p.category,
        "country": p.country,
        "currency": p.currency,
        "min": p.min,
        "max": p.max,
        "increment": "0.01",
        "denominations": null,
        "product_image_url": null,
        "catalog_info": null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        for msg in ["", "a", "ab", "{\"x402Version\":2,\"accepts\":[]}"] {
            assert_eq!(
                b64_decode(&b64_encode(msg.as_bytes())).unwrap(),
                msg.as_bytes()
            );
        }
    }

    #[test]
    fn luhn_pan_is_valid() {
        let pan = pan_for(1);
        assert_eq!(pan.len(), 16);
        let sum: u32 = pan
            .chars()
            .rev()
            .enumerate()
            .map(|(i, c)| {
                let d = c.to_digit(10).unwrap();
                if i % 2 == 1 {
                    let x = d * 2;
                    if x > 9 { x - 9 } else { x }
                } else {
                    d
                }
            })
            .sum();
        assert_eq!(sum % 10, 0);
    }

    #[test]
    fn fees_match_docs() {
        // intl: amount + 3.8%
        assert_eq!(round2(100.0 + round2(100.0 * 0.038)), 103.80);
        // push-to-card: +4.8% min 1.50
        assert_eq!(round2((10.0 * 0.048f64).max(1.50)), 1.50);
        assert_eq!(round2((100.0 * 0.048f64).max(1.50)), 4.80);
    }

    #[test]
    fn readable_timestamp_format() {
        assert_eq!(readable(1_774_000_000_000), "3/20/2026, 9:46:40 AM");
    }
}
