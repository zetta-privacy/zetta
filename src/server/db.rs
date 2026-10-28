//! Durable append-only log: registrations + card orders + deposits + withdraws
//! (PostgreSQL). Tables are created externally (src/schemas/*.sql).
//!
//! Accounting model (per pubkey_x):
//!   available  = Σ(value) over proven, registered deposits
//!   reserved   = Σ over non-failed latest rows: card_orders + withdraws amounts
//!   balance    = available − reserved
//!
//! 'closed' cards keep counting (the money is prepaid and unrecoverable);
//! closing only stops the card from being the active one.

use crate::burn::address_to_fr;
use crate::ids::user_id;
use crate::zkp::poseidon2;
use crate::zkp::poseidon3;
use alloy::primitives::U256;
use ark_bn254::{Fq, Fr};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Affine as G2Affine;
use ark_grumpkin::Projective as G2;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Postgres, Row};
use std::time::UNIX_EPOCH;

pub fn fr_to_blob<F: PrimeField>(x: F) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

pub fn blob_to_fr<F: PrimeField>(b: &[u8]) -> F {
    F::from_be_bytes_mod_order(b)
}

pub fn fr_to_u256(x: Fr) -> U256 {
    U256::from_be_slice(&fr_to_blob(x))
}

pub fn blob_to_u256(b: &[u8]) -> U256 {
    U256::from_be_slice(b)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Schnorr over grumpkin: z·G == R + e·P with e = poseidon3(R.x, P.x, msg).
/// Pubkey validity (on-curve, non-zero) is the caller's job.
fn schnorr_verify(pubkey: G2Affine, msg: Fr, sig_r: G2Affine, sig_z: Fq) -> Result<bool, String> {
    let e_fr = poseidon3(sig_r.x, pubkey.x, msg).map_err(|e| e.to_string())?;
    let e = Fq::from_be_bytes_mod_order(&e_fr.into_bigint().to_bytes_be());
    Ok((G2::generator() * sig_z).into_affine()
        == (G2::from(sig_r) + G2::from(pubkey) * e).into_affine())
}

/// Next per-user order nonce = user's order count. Runs on any executor
/// (pool for the read endpoint, locked tx for the atomic insert).
async fn card_nonce<'e, E>(exec: E, pubkey_x: Fr) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar("SELECT COALESCE(MAX(nonce), -1) + 1 FROM card_orders WHERE pubkey_x = $1")
        .bind(fr_to_blob(pubkey_x))
        .fetch_one(exec)
        .await
}

async fn withdraw_nonce<'e, E>(exec: E, pubkey_x: Fr) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar("SELECT COALESCE(MAX(nonce), -1) + 1 FROM withdraws WHERE pubkey_x = $1")
        .bind(fr_to_blob(pubkey_x))
        .fetch_one(exec)
        .await
}

/// Global advisory-lock key serializing all reservations (cards + withdraws).
const SPEND_LOCK_KEY: i64 = 0x5A45_5454_41; // "ZETTA"

/// Domain tag bound into card-order signatures. Withdraws must use a
/// different one so a card signature can never be replayed there.
const CARD_ORDER_DOMAIN: u64 = 0x6361_7264; // "card"
/// Domain tag for withdraw-request signatures (cards use CARD_ORDER_DOMAIN).
const WITHDRAW_DOMAIN: u64 = 0x7769_7468; // "with"

#[derive(Clone, Debug)]
pub struct Registration {
    pub address: [u8; 20],
    pub created_at: i64,
    pub pubkey_x: Fr,
    pub pubkey_y: Fr,
    pub sig_r_x: Fr,
    pub sig_r_y: Fr,
    pub sig_z: Fq,
    pub salt: Fr,
    pub recipient: Fr,
    pub registered_from: i64,
    pub user_id: String,
}

#[derive(Clone, Debug)]
pub struct PendingWithdraw {
    pub ref_: String,
    pub amount: U256,
    pub destination: [u8; 20],
}

#[derive(Clone, Debug)]
pub struct CardOrderRow {
    pub provider_ref: String,
    pub amount: U256,
    pub status: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct WithdrawRow {
    pub ref_: String,
    pub amount: U256,
    pub destination: [u8; 20],
    pub status: String,
    pub created_at: i64,
}

#[derive(Clone)]
pub struct Db(PgPool);

fn row_to_registration(row: &sqlx::postgres::PgRow) -> Result<Registration, sqlx::Error> {
    let addr: Vec<u8> = row.try_get("burn_address")?;
    let address: [u8; 20] = addr
        .try_into()
        .map_err(|_| sqlx::Error::Decode("bad address length".into()))?;
    Ok(Registration {
        address,
        created_at: row.try_get("created_at")?,
        pubkey_x: blob_to_fr(&row.try_get::<Vec<u8>, _>("pubkey_x")?),
        pubkey_y: blob_to_fr(&row.try_get::<Vec<u8>, _>("pubkey_y")?),
        sig_r_x: blob_to_fr(&row.try_get::<Vec<u8>, _>("sig_r_x")?),
        sig_r_y: blob_to_fr(&row.try_get::<Vec<u8>, _>("sig_r_y")?),
        sig_z: blob_to_fr(&row.try_get::<Vec<u8>, _>("sig_z")?),
        salt: blob_to_fr(&row.try_get::<Vec<u8>, _>("salt")?),
        recipient: blob_to_fr(&row.try_get::<Vec<u8>, _>("recipient")?),
        registered_from: row.try_get("registered_from")?,
        user_id: row.try_get("user_id")?,
    })
}

/// Σ reserved (non-failed latest rows): cards amount, withdraws amount.
async fn reserved<'e, E>(exec: E, pubkey_x: Fr) -> Result<U256, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut total = U256::ZERO;

    let card_rows = sqlx::query(
        "SELECT DISTINCT ON (provider_ref) amount, status
         FROM card_orders
         WHERE pubkey_x = $1
         ORDER BY provider_ref, id DESC",
    )
    .bind(fr_to_blob(pubkey_x))
    .fetch_all(exec)
    .await?;
    for r in &card_rows {
        if r.try_get::<String, _>("status")? == "failed" {
            continue; // failed releases; pending/succeeded/closed all count
        }
        let amount: Vec<u8> = r.try_get("amount")?;
        total += blob_to_u256(&amount);
    }

    Ok(total)
}

async fn reserved_withdraws<'e, E>(exec: E, pubkey_x: Fr) -> Result<U256, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut total = U256::ZERO;
    let rows = sqlx::query(
        "SELECT DISTINCT ON (ref) amount, status
         FROM withdraws
         WHERE pubkey_x = $1
         ORDER BY ref, id DESC",
    )
    .bind(fr_to_blob(pubkey_x))
    .fetch_all(exec)
    .await?;
    for r in &rows {
        if r.try_get::<String, _>("status")? == "failed" {
            continue;
        }
        let amount: Vec<u8> = r.try_get("amount")?;
        total += blob_to_u256(&amount);
    }
    Ok(total)
}

impl Db {
    pub async fn open(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let options: PgConnectOptions = url.parse()?;
        let pool = PgPoolOptions::new()
            .connect_with(options.statement_cache_capacity(0))
            .await?;
        Ok(Self(pool))
    }

    pub async fn next_card_nonce(&self, pubkey_x: Fr) -> Result<i64, Box<dyn std::error::Error>> {
        Ok(card_nonce(&self.0, pubkey_x).await?)
    }

    pub async fn next_withdraw_nonce(
        &self,
        pubkey_x: Fr,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        Ok(withdraw_nonce(&self.0, pubkey_x).await?)
    }

    /// Atomically verify the request signature, check balance, and record the
    /// withdraw ('pending'). Signed message:
    /// poseidon3(WITHDRAW_DOMAIN, poseidon2(amount, destination_fr), nonce).
    /// Debited is `amount`; destination receives `amount` in full.
    /// `nonce` is client-supplied; must equal the user's next nonce.
    pub async fn try_withdraw(
        &self,
        pubkey_x: Fr,
        pubkey_y: Fr,
        amount: Fr,
        nonce: i64,
        available: U256,
        destination: [u8; 20],
        sig_r: G2Affine,
        sig_z: Fq,
        ref_: &str,
    ) -> Result<U256, String> {
        let pk = G2Affine::new_unchecked(pubkey_x, pubkey_y);
        if !pk.is_on_curve() {
            return Err("stored pubkey invalid".into());
        }
        let amount_u256 = fr_to_u256(amount);

        let mut tx = self.0.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(SPEND_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        let dup = sqlx::query("SELECT 1 FROM withdraws WHERE ref = $1")
            .bind(ref_)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        if dup.is_some() {
            return Err(format!("withdraw ref {ref_} already exists"));
        }

        let expected = withdraw_nonce(&mut *tx, pubkey_x)
            .await
            .map_err(|e| e.to_string())?;
        if nonce != expected {
            return Err(format!("bad nonce: expected {expected}"));
        }

        // Schnorr over msg = poseidon3(WITHDRAW_DOMAIN, poseidon2(amount, dest_fr), nonce).
        let inner = poseidon2(amount, address_to_fr(destination)).map_err(|e| e.to_string())?;
        let msg = poseidon3(Fr::from(WITHDRAW_DOMAIN), inner, Fr::from(nonce as u64))
            .map_err(|e| e.to_string())?;
        if !schnorr_verify(pk, msg, sig_r, sig_z)? {
            return Err("bad withdraw signature".into());
        }

        let cards = reserved(&mut *tx, pubkey_x)
            .await
            .map_err(|e| e.to_string())?;
        let wds = reserved_withdraws(&mut *tx, pubkey_x)
            .await
            .map_err(|e| e.to_string())?;
        let spent = cards + wds;

        let new_spent = spent + amount_u256;
        if new_spent > available {
            return Err(format!(
                "insufficient balance: available {available}, spent {spent}, requested {amount_u256}"
            ));
        }

        let amount_bytes: [u8; 32] = amount_u256.to_be_bytes();
        sqlx::query(
            "INSERT INTO withdraws (ref, pubkey_x, user_id, amount, destination, status, nonce, created_at)
             VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)",
        )
        .bind(ref_)
        .bind(fr_to_blob(pubkey_x))
        .bind(user_id(pubkey_x))
        .bind(amount_bytes.as_slice())
        .bind(destination.as_slice())
        .bind(nonce)
        .bind(unix_now())
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(new_spent)
    }

    /// Append a 'succeeded'/'failed' transition to a request still in 'pending'.
    /// Transition rows inherit the request's nonce (trigger exempts them).
    pub async fn settle_withdraw(
        &self,
        ref_: &str,
        status: &str,
        tx_hash: Option<[u8; 32]>,
        error: Option<&str>,
    ) -> Result<(), String> {
        let res = sqlx::query(
            "INSERT INTO withdraws (ref, pubkey_x, user_id, amount, destination, status, nonce, tx_hash, error, created_at, resolved_at)
             SELECT ref, pubkey_x, user_id, amount, destination, $1, nonce, $2, $3, created_at, $4
             FROM withdraws
             WHERE ref = $5
               AND id = (SELECT MAX(id) FROM withdraws WHERE ref = $5)
               AND status = 'pending'",
        )
        .bind(status)
        .bind(tx_hash.map(|h| h.to_vec()))
        .bind(error)
        .bind(unix_now())
        .bind(ref_)
        .execute(&self.0)
        .await
        .map_err(|e| e.to_string())?;
        if res.rows_affected() != 1 {
            return Err(format!("withdraw {ref_} not pending (or missing)"));
        }
        Ok(())
    }

    /// Unsettled requests, FIFO. A 'pending' row with no later transition.
    pub async fn pending_withdraws(
        &self,
    ) -> Result<Vec<PendingWithdraw>, Box<dyn std::error::Error>> {
        let rows = sqlx::query(
            "SELECT w.ref, w.amount, w.destination
             FROM withdraws w
             WHERE w.status = 'pending'
               AND NOT EXISTS (
                   SELECT 1 FROM withdraws x WHERE x.ref = w.ref AND x.id > w.id
               )
             ORDER BY w.created_at ASC, w.id ASC",
        )
        .fetch_all(&self.0)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let dest: Vec<u8> = r.try_get("destination")?;
            out.push(PendingWithdraw {
                ref_: r.try_get("ref")?,
                amount: blob_to_u256(&r.try_get::<Vec<u8>, _>("amount")?),
                destination: dest
                    .try_into()
                    .map_err(|_| sqlx::Error::Decode("bad destination length".into()))?,
            });
        }
        Ok(out)
    }

    /// Latest row per request, newest first — the feed behind GET /withdraws/:pubkey_x.
    pub async fn withdraw_history(&self, pubkey_x: Fr) -> Result<Vec<WithdrawRow>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT DISTINCT ON (ref) ref, amount, destination, status, created_at
             FROM withdraws
             WHERE pubkey_x = $1
             ORDER BY ref, id DESC",
        )
        .bind(fr_to_blob(pubkey_x))
        .fetch_all(&self.0)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let dest: Vec<u8> = r.try_get("destination")?;
            out.push(WithdrawRow {
                ref_: r.try_get("ref")?,
                amount: blob_to_u256(&r.try_get::<Vec<u8>, _>("amount")?),
                destination: dest
                    .try_into()
                    .map_err(|_| sqlx::Error::Decode("bad destination length".into()))?,
                status: r.try_get("status")?,
                created_at: r.try_get("created_at")?,
            });
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at)); // DISTINCT ON loses chronology
        Ok(out)
    }

    pub async fn insert_registration(
        &self,
        r: &Registration,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query(
            "INSERT INTO registrations (burn_address, created_at, pubkey_x, pubkey_y, sig_r_x, sig_r_y, sig_z, salt, recipient, user_id, registered_from)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(r.address.as_slice())
        .bind(r.created_at)
        .bind(fr_to_blob(r.pubkey_x))
        .bind(fr_to_blob(r.pubkey_y))
        .bind(fr_to_blob(r.sig_r_x))
        .bind(fr_to_blob(r.sig_r_y))
        .bind(fr_to_blob(r.sig_z))
        .bind(fr_to_blob(r.salt))
        .bind(fr_to_blob(r.recipient))
        .bind(&r.user_id)
        .bind(r.registered_from)
        .execute(&self.0)
        .await?;
        Ok(())
    }

    /// Latest row per address — for boot-time hydration.
    pub async fn latest_registrations(
        &self,
    ) -> Result<Vec<Registration>, Box<dyn std::error::Error>> {
        let rows = sqlx::query(
            "SELECT burn_address, created_at, pubkey_x, pubkey_y, sig_r_x, sig_r_y, sig_z, salt, recipient, user_id,
                (SELECT MIN(registered_from) FROM registrations x WHERE x.burn_address = r.burn_address) AS registered_from
            FROM registrations r
            WHERE created_at = (
                SELECT MAX(created_at) FROM registrations WHERE burn_address = r.burn_address
            )",
        )
        .fetch_all(&self.0)
        .await?;
        let regs = rows
            .iter()
            .map(row_to_registration)
            .collect::<Result<Vec<Registration>, sqlx::Error>>()?;
        Ok(regs)
    }

    pub async fn latest_registration_by_pubkey(
        &self,
        pubkey_x: Fr,
    ) -> Result<Option<Registration>, Box<dyn std::error::Error>> {
        let row = sqlx::query(
            "SELECT burn_address, created_at, pubkey_x, pubkey_y, sig_r_x, sig_r_y, sig_z, salt, recipient, user_id,
                (SELECT MIN(registered_from) FROM registrations x WHERE x.burn_address = r.burn_address) AS registered_from
             FROM registrations r
             WHERE pubkey_x = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(fr_to_blob(pubkey_x))
        .fetch_optional(&self.0)
        .await?;
        row.as_ref()
            .map(row_to_registration)
            .transpose()
            .map_err(Into::into)
    }

    /// Latest pubkey registered under a display user id (Crockford handle).
    pub async fn pubkey_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<Fr>, Box<dyn std::error::Error>> {
        let row = sqlx::query(
            "SELECT pubkey_x FROM registrations WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.0)
        .await?;
        match row {
            None => Ok(None),
            Some(r) => {
                let bytes: Vec<u8> = r.try_get("pubkey_x")?;
                Ok(Some(blob_to_fr(&bytes)))
            }
        }
    }

    // ---- spend accounting (cards + withdraws) ----

    /// Total reserved across cards and withdraws — what /balance subtracts.
    pub async fn total_spent(&self, pubkey_x: Fr) -> Result<U256, Box<dyn std::error::Error>> {
        let cards = reserved(&self.0, pubkey_x).await?;
        let wds = reserved_withdraws(&self.0, pubkey_x).await?;
        Ok(cards + wds)
    }

    /// Atomically verify the order signature, check balance, and record the
    /// order ('pending'). Signed message:
    /// poseidon3(CARD_ORDER_DOMAIN, amount, nonce), nonce = user's order count
    /// — this insert consumes it, so the signature is valid exactly once.
    /// Verification happens inside the advisory lock: two requests bearing the
    /// same signature cannot both pass.
    pub async fn try_card_order(
        &self,
        pubkey_x: Fr,
        pubkey_y: Fr,
        amount: Fr,
        nonce: i64,
        available: U256,
        sig_r: G2Affine,
        sig_z: Fq,
        provider: &str,
        provider_ref: &str,
        max_cards: i64,
        window_days: i64,
    ) -> Result<U256, String> {
        let pk = G2Affine::new_unchecked(pubkey_x, pubkey_y);
        if !pk.is_on_curve() {
            return Err("stored pubkey invalid".into());
        }

        let mut tx = self.0.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(SPEND_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        let expected = card_nonce(&mut *tx, pubkey_x)
            .await
            .map_err(|e| e.to_string())?;
        if nonce != expected {
            return Err(format!("bad nonce: expected {expected}"));
        }

        // Schnorr over msg = poseidon3(CARD_ORDER_DOMAIN, amount, nonce).
        let msg = poseidon3(Fr::from(CARD_ORDER_DOMAIN), amount, Fr::from(nonce as u64))
            .map_err(|e| e.to_string())?;
        if !schnorr_verify(pk, msg, sig_r, sig_z)? {
            return Err("bad order signature".into());
        }

        let cards = reserved(&mut *tx, pubkey_x)
            .await
            .map_err(|e| e.to_string())?;
        let wds = reserved_withdraws(&mut *tx, pubkey_x)
            .await
            .map_err(|e| e.to_string())?;
        let spent = cards + wds;

        let amount_u256 = fr_to_u256(amount);
        let new_spent = spent + amount_u256;
        if new_spent > available {
            return Err(format!(
                "insufficient balance: available {available}, spent {spent}, requested {amount_u256}"
            ));
        }

        // Rolling issuance limit: max `max_cards` non-failed orders per user
        // in the last `window_days`, checked under the spend lock.
        let recent: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM (
                 SELECT DISTINCT ON (provider_ref) status
                 FROM card_orders
                 WHERE pubkey_x = $1 AND created_at >= $2
                 ORDER BY provider_ref, id DESC
             ) t WHERE status != 'failed'",
        )
        .bind(fr_to_blob(pubkey_x))
        .bind(unix_now() - window_days * 86_400)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        if recent >= max_cards {
            return Err(format!(
                "card limit reached: max {max_cards} cards per {window_days} days"
            ));
        }

        let amount_bytes: [u8; 32] = amount_u256.to_be_bytes();
        sqlx::query(
                "INSERT INTO card_orders (pubkey_x, user_id, amount, provider, provider_ref, status, nonce, created_at)
                 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)",
            )
            .bind(fr_to_blob(pubkey_x))
            .bind(user_id(pubkey_x))
            .bind(amount_bytes.as_slice())
            .bind(provider)
            .bind(provider_ref)
            .bind(nonce)
            .bind(unix_now())
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;

        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(new_spent)
    }

    /// Append a 'succeeded'/'failed' transition to an order still in 'pending'.
    /// On success, `card` carries the provider's card id + auth tokens;
    /// transitions without values inherit the previous row's (COALESCE), so a
    /// later token-refresh row doesn't erase them.
    pub async fn settle_card_order(
        &self,
        provider_ref: &str,
        status: &str,
        error: Option<&str>,
        card: Option<(&str, &str, &str)>, // (card_id, id_token, refresh_token)
    ) -> Result<(), String> {
        let res = sqlx::query(
            "INSERT INTO card_orders (pubkey_x, user_id, amount, provider, provider_ref, status, error, nonce, created_at, resolved_at, card_id, id_token, refresh_token)
            SELECT pubkey_x, user_id, amount, provider, provider_ref, $1, $2, nonce, created_at, $3,
                   COALESCE($4, card_id), COALESCE($5, id_token), COALESCE($6, refresh_token)
            FROM card_orders
            WHERE provider_ref = $7
              AND id = (SELECT MAX(id) FROM card_orders WHERE provider_ref = $7)
              AND status = 'pending'",
        )
        .bind(status)
        .bind(error)
        .bind(unix_now())
        .bind(card.map(|c| c.0))
        .bind(card.map(|c| c.1))
        .bind(card.map(|c| c.2))
        .bind(provider_ref)
        .execute(&self.0)
        .await
        .map_err(|e| e.to_string())?;
        if res.rows_affected() != 1 {
            return Err(format!("order {provider_ref} not pending (or missing)"));
        }
        Ok(())
    }

    /// Append a 'closed' transition to a succeeded order. No balance effect
    /// (prepaid money is gone); the card just stops being the active one.
    pub async fn close_card_order(&self, provider_ref: &str) -> Result<(), String> {
        let res = sqlx::query(
            "INSERT INTO card_orders (pubkey_x, user_id, amount, provider, provider_ref, status, nonce, created_at, resolved_at)
            SELECT pubkey_x, user_id, amount, provider, provider_ref, 'closed', nonce, created_at, $1
             FROM card_orders
             WHERE provider_ref = $2
               AND id = (SELECT MAX(id) FROM card_orders WHERE provider_ref = $2)
               AND status = 'succeeded'",
        )
        .bind(unix_now())
        .bind(provider_ref)
        .execute(&self.0)
        .await
        .map_err(|e| e.to_string())?;
        if res.rows_affected() != 1 {
            return Err(format!("order {provider_ref} not succeeded (or missing)"));
        }
        Ok(())
    }

    /// Latest row per order, newest first — the feed behind GET /cards/:pubkey_x.
    pub async fn card_orders(&self, pubkey_x: Fr) -> Result<Vec<CardOrderRow>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT DISTINCT ON (provider_ref) provider_ref, amount, status, created_at
             FROM card_orders
             WHERE pubkey_x = $1
             ORDER BY provider_ref, id DESC",
        )
        .bind(fr_to_blob(pubkey_x))
        .fetch_all(&self.0)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(CardOrderRow {
                provider_ref: r.try_get("provider_ref")?,
                amount: blob_to_u256(&r.try_get::<Vec<u8>, _>("amount")?),
                status: r.try_get("status")?,
                created_at: r.try_get("created_at")?,
            });
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at)); // DISTINCT ON loses chronology
        Ok(out)
    }

    /// All blacklisted sender addresses.
    pub async fn blacklist(&self) -> Result<Vec<[u8; 20]>, sqlx::Error> {
        let rows = sqlx::query("SELECT address FROM blacklist")
            .fetch_all(&self.0)
            .await?;
        rows.iter()
            .map(|r| {
                let v: Vec<u8> = r.try_get("address")?;
                v.try_into()
                    .map_err(|_| sqlx::Error::Decode("bad blacklist address length".into()))
            })
            .collect()
    }

    /// Number of distinct registered pubkeys (unique users).
    pub async fn unique_user_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT COUNT(DISTINCT pubkey_x) FROM registrations")
            .fetch_one(&self.0)
            .await
    }
}

#[derive(Clone, Debug)]
pub struct CardLink {
    pub status: String,
    pub card_id: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

impl Db {
    /// Latest row of one order with provider metadata, for the details proxy.
    pub async fn card_link(
        &self,
        pubkey_x: Fr,
        provider_ref: &str,
    ) -> Result<Option<CardLink>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT status, card_id, id_token, refresh_token FROM card_orders
             WHERE pubkey_x = $1 AND provider_ref = $2
             ORDER BY id DESC LIMIT 1",
        )
        .bind(fr_to_blob(pubkey_x))
        .bind(provider_ref)
        .fetch_optional(&self.0)
        .await?;
        Ok(row.map(|r| CardLink {
            status: r.try_get("status").unwrap_or_default(),
            card_id: r.try_get("card_id").unwrap_or_default(),
            id_token: r.try_get("id_token").unwrap_or_default(),
            refresh_token: r.try_get("refresh_token").unwrap_or_default(),
        }))
    }

    /// Token rotation, append-only: a fresh 'succeeded' row carrying the new
    /// tokens (copying everything else). Latest row wins everywhere already.
    pub async fn refresh_card_tokens(
        &self,
        provider_ref: &str,
        id_token: &str,
        refresh_token: &str,
    ) -> Result<(), String> {
        let res = sqlx::query(
            "INSERT INTO card_orders (pubkey_x, user_id, amount, provider, provider_ref, status, error, nonce, created_at, resolved_at, card_id, id_token, refresh_token)
            SELECT pubkey_x, user_id, amount, provider, provider_ref, status, error, nonce, created_at, $1, card_id, $2, $3
            FROM card_orders
            WHERE provider_ref = $4
              AND id = (SELECT MAX(id) FROM card_orders WHERE provider_ref = $4)
              AND status = 'succeeded'",
        )
        .bind(unix_now())
        .bind(id_token)
        .bind(refresh_token)
        .bind(provider_ref)
        .execute(&self.0)
        .await
        .map_err(|e| e.to_string())?;
        if res.rows_affected() != 1 {
            return Err(format!("order {provider_ref} not succeeded (or missing)"));
        }
        Ok(())
    }
}
