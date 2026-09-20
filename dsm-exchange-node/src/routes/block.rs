// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /block/{n} — returns page N of incoming deposits (to_device == our device_id).
//!
//! Block size is fixed at PAGE_SIZE transactions. The latest block number is
//! floor(deposit_count / PAGE_SIZE), returned by GET /state.

use axum::{
    extract::{Path, State},
    Json,
};
use dsm_sdk::storage::client_db::get_transaction_history;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{error::AppError, AppState};

pub const PAGE_SIZE: usize = 100;

/// GET /block/{n}
pub async fn get_block(
    Path(n): Path<u64>,
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let all_txs = get_transaction_history(None, Some(1_000_000))
        .map_err(|e| AppError::Sdk(format!("get_transaction_history: {e}")))?;

    let start = n as usize * PAGE_SIZE;
    let page: Vec<_> = all_txs.into_iter().skip(start).take(PAGE_SIZE).collect();

    Ok(Json(json!({
        "block": n,
        "transactions": page.iter().map(|tx| json!({
            "tx_id":        tx.tx_id,
            "tx_hash":      b32_or_hex_to_hex(&tx.tx_hash),
            "from_device":  b32_or_hex_to_hex(&tx.from_device),
            "to_device":    b32_or_hex_to_hex(&tx.to_device),
            "amount":       tx.amount,
            "tx_type":      tx.tx_type,
            "status":       tx.status,
            "chain_height": tx.chain_height,
            "memo":         extract_memo(&tx.metadata),
        })).collect::<Vec<_>>(),
        "count": page.len(),
    })))
}

/// Extracts memo from the metadata HashMap (stored as raw bytes under key "memo").
fn extract_memo(metadata: &HashMap<String, Vec<u8>>) -> String {
    metadata
        .get("memo")
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .unwrap_or_default()
}

/// Converts a Crockford Base32 string to lowercase hex.
/// If the input is already valid hex (or any other format), returns it unchanged.
pub fn b32_or_hex_to_hex(s: &str) -> String {
    match dsm_sdk::util::text_id::decode_base32_crockford(s) {
        Some(bytes) => hex::encode(&bytes),
        None => s.to_string(),
    }
}

/// Reads our device_id from AppState and converts to Crockford Base32,
/// which is the format SDK stores `to_device` / `from_device` in the DB.
pub async fn our_device_id_b32(state: &Arc<AppState>) -> Result<String, AppError> {
    let id = state.identity.read().await;
    match &*id {
        Some(identity) => hex::decode(&identity.device_id_hex)
            .map(|b| dsm_sdk::util::text_id::encode_base32_crockford(&b))
            .map_err(|e| AppError::Sdk(format!("device_id hex decode: {e}"))),
        None => Err(AppError::SdkNotReady("identity not ready".to_string())),
    }
}
