//! Database layer.  Two-schema design — one table per storage
//! scenario — so a single `mmiyc-server` binary can be run twice
//! (once per scenario) on the same DB to make A/B comparisons
//! cheap.
//!
//! Schemas are created idempotently on startup if they don't
//! already exist.  No migrations crate is pulled in; the
//! schema's small enough that hand-rolled SQL is simpler.

use anyhow::Result;
use sqlx::SqlitePool;

/// Initialise the SQLite pool and ensure both schemas exist.
pub async fn open(database_url: &str) -> Result<SqlitePool> {
    let pool = SqlitePool::connect(database_url).await?;
    init_schemas(&pool).await?;
    Ok(pool)
}

async fn init_schemas(pool: &SqlitePool) -> Result<()> {
    // ------- PII schema -------
    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS users_pii (
            user_id      TEXT PRIMARY KEY,
            dob_days     INTEGER NOT NULL,
            country_code TEXT    NOT NULL,
            postcode     TEXT,
            email        TEXT    NOT NULL,
            income_pence INTEGER NOT NULL,
            sex          TEXT    NOT NULL,
            created_at   INTEGER NOT NULL
        )
        ",
    )
    .execute(pool).await?;

    // ------- Proofs schema -------
    sqlx::query(
        r"
        CREATE TABLE IF NOT EXISTS users_proofs (
            user_id              TEXT PRIMARY KEY,
            age_proof            BLOB,
            age_policy_json      TEXT,
            country_proof        BLOB,
            country_policy_json  TEXT,
            email_hash           BLOB,    -- separate hashed email for login if needed
            created_at           INTEGER NOT NULL
        )
        ",
    )
    .execute(pool).await?;
    Ok(())
}

// ─── PII inserts / reads ──────────────────────────────────────────

/// One row in the `users_pii` table.
#[allow(missing_docs)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PiiRow {
    pub user_id:      String,
    pub dob_days:     i64,
    pub country_code: String,
    pub postcode:     Option<String>,
    pub email:        String,
    pub income_pence: i64,
    pub sex:          String,
    pub created_at:   i64,
}

/// Insert a PII row.
pub async fn insert_pii(pool: &SqlitePool, row: &PiiRow) -> Result<()> {
    sqlx::query(
        r"INSERT INTO users_pii
            (user_id, dob_days, country_code, postcode, email, income_pence, sex, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.user_id)
    .bind(row.dob_days)
    .bind(&row.country_code)
    .bind(&row.postcode)
    .bind(&row.email)
    .bind(row.income_pence)
    .bind(&row.sex)
    .bind(row.created_at)
    .execute(pool).await?;
    Ok(())
}

/// Fetch a PII row by user_id.
pub async fn fetch_pii(pool: &SqlitePool, user_id: &str) -> Result<Option<PiiRow>> {
    let row = sqlx::query_as::<_, PiiRow>("SELECT * FROM users_pii WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(pool).await?;
    Ok(row)
}

// ─── Proofs inserts / reads ──────────────────────────────────────

/// One row in the `users_proofs` table.
#[allow(missing_docs)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProofsRow {
    pub user_id:             String,
    pub age_proof:           Option<Vec<u8>>,
    pub age_policy_json:     Option<String>,
    pub country_proof:       Option<Vec<u8>>,
    pub country_policy_json: Option<String>,
    pub email_hash:          Option<Vec<u8>>,
    pub created_at:          i64,
}

/// Insert a proofs row.
pub async fn insert_proofs(pool: &SqlitePool, row: &ProofsRow) -> Result<()> {
    sqlx::query(
        r"INSERT INTO users_proofs
            (user_id, age_proof, age_policy_json, country_proof, country_policy_json, email_hash, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.user_id)
    .bind(&row.age_proof)
    .bind(&row.age_policy_json)
    .bind(&row.country_proof)
    .bind(&row.country_policy_json)
    .bind(&row.email_hash)
    .bind(row.created_at)
    .execute(pool).await?;
    Ok(())
}

/// Fetch a proofs row by user_id.
pub async fn fetch_proofs(pool: &SqlitePool, user_id: &str) -> Result<Option<ProofsRow>> {
    let row = sqlx::query_as::<_, ProofsRow>("SELECT * FROM users_proofs WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(pool).await?;
    Ok(row)
}

// ─── Storage stats (small helper used by the bench harness) ───────

/// Total bytes stored in each table — used by the storage analysis.
pub async fn count_rows_pii(pool: &SqlitePool) -> Result<i64> {
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users_pii").fetch_one(pool).await?;
    Ok(n.0)
}

/// Total rows in the proofs table.
pub async fn count_rows_proofs(pool: &SqlitePool) -> Result<i64> {
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users_proofs").fetch_one(pool).await?;
    Ok(n.0)
}
