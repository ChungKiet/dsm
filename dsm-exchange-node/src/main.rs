// SPDX-License-Identifier: MIT OR Apache-2.0
//! DSM Exchange Node — Rust sidecar that wraps dsm_sdk and exposes a JSON
//! HTTP API consumed by the Go adapters library.

mod config;
mod error;
mod routes;
mod sdk;

use std::sync::Arc;
use tokio::sync::RwLock;

use axum::{
    routing::{get, post},
    Router,
};

use clap::Parser;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::Config;
use sdk::IdentityState;

/// Shared application state accessible to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub identity: Arc<RwLock<Option<IdentityState>>>,
}

#[derive(Parser)]
#[command(name = "dsm-exchange-node", about = "DSM exchange sidecar")]
struct Args {
    /// Path to config TOML file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dsm_exchange_node=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let cfg = Config::load(&args.config)?;
    let listen = cfg.http.listen.clone();

    tracing::info!("Starting dsm-exchange-node (node_id={})", cfg.node.id);
    tracing::info!("Storage endpoints: {:?}", cfg.storage.endpoints);

    // Bootstrap SDK + identity (may create genesis on first run)
    let identity = sdk::bootstrap(&cfg).await?;

    // Start background inbox poller — auto-syncs every 60s (8s eager after activity).
    // This processes incoming transfers without requiring manual POST /sync calls.
    if let Some(router) = dsm_sdk::bridge::app_router() {
        router.invoke(dsm_sdk::bridge::AppInvoke {
            method: "inbox.startPoller".to_string(),
            args: vec![],
        }).await;
        tracing::info!("Inbox background poller started");
    }

    let state = Arc::new(AppState {
        config: cfg,
        identity: Arc::new(RwLock::new(Some(identity))),
    });

    let app = Router::new()
        // Health
        .route("/health", get(routes::health::get_health))
        // Identity
        .route("/identity", get(routes::identity::get_identity))
        // State (tick / block number)
        .route("/state", get(routes::state::get_state))
        // Block (paginated deposits)
        .route("/block/{n}", get(routes::block::get_block))
        // Balance
        .route("/balance", get(routes::balance::get_balance))
        .route("/balances", get(routes::balance::get_balances))
        // Transfer
        .route("/transfer", post(routes::transfer::post_transfer))
        // Transaction lookup
        .route("/transaction/{hash}", get(routes::transaction::get_transaction))
        // Inbox
        .route("/inbox", get(routes::inbox::get_inbox))
        .route("/inbox/ack", post(routes::inbox::post_inbox_ack))
        // Contacts
        .route("/contacts", post(routes::contacts::add_contact))
        // Sync (pull inbox + push pending transactions)
        .route("/sync", post(routes::sync::post_sync))
        // Faucet (testnet only)
        .route("/faucet", post(routes::faucet::post_faucet))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    tracing::info!("Listening on {listen}");
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
