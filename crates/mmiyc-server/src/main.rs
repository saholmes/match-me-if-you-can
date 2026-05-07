use mmiyc_server::router::build_router;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let bind = std::env::var("MMIYC_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    info!("Match Me If You Can server starting on {}", bind);

    let app = build_router();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
