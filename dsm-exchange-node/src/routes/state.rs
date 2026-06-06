// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /state — returns the latest block number (floor of tx_count / PAGE_SIZE).

use axum::{extract::State, Json};
use dsm_sdk::storage::client_db::get_transaction_history;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{error::AppError, AppState};
use super::block::PAGE_SIZE;

/// GET /state
pub async fn get_state(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let all_txs = get_transaction_history(None, Some(1_000_000))
        .map_err(|e| AppError::Sdk(format!("get_transaction_history: {e}")))?;

    let tick = all_txs.len() as u64 / PAGE_SIZE as u64;

    Ok(Json(json!({ "tick": tick })))
}
