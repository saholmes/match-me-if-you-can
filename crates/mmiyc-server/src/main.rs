use std::path::PathBuf;

use mmiyc_server::{db, router::build_router, AppState, Scenario};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind = std::env::var("MMIYC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let database_url = std::env::var("MMIYC_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:mmiyc.db?mode=rwc".into());
    let scenario = std::env::var("MMIYC_SCENARIO")
        .ok()
        .and_then(|s| Scenario::from_str(&s))
        .unwrap_or(Scenario::Proofs);

    // Static directory for the browser demo.  Defaults to ./frontend
    // relative to the current working directory; override with
    // MMIYC_STATIC_DIR.  When the directory doesn't exist, the server
    // simply returns 404 for non-API paths.
    let static_dir = std::env::var("MMIYC_STATIC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("frontend"));
    let static_dir = if static_dir.is_dir() { Some(static_dir) } else { None };

    info!(
        "Match Me If You Can server starting on {} ({:?} scenario, db={}, static={:?})",
        bind, scenario, database_url, static_dir,
    );

    let pool = db::open(&database_url).await?;
    let state = AppState { pool, scenario };
    let app = build_router(state, static_dir);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
