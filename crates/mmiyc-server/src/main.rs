use mmiyc_server::{db, router::build_router, AppState, Scenario};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // Configuration via env vars — swap for clap if/when more args land.
    let bind = std::env::var("MMIYC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let database_url = std::env::var("MMIYC_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:mmiyc.db?mode=rwc".into());
    let scenario = std::env::var("MMIYC_SCENARIO")
        .ok()
        .and_then(|s| Scenario::from_str(&s))
        .unwrap_or(Scenario::Proofs);

    info!(
        "Match Me If You Can server starting on {} ({:?} scenario, db={})",
        bind, scenario, database_url,
    );

    let pool = db::open(&database_url).await?;
    let state = AppState { pool, scenario };
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
