// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /transaction/:hash — look up a local transfer receipt by tx_hash.
//!
//! Accepts the hash in either hex (as returned by POST /transfer) or
//! Crockford Base32 (the SDK's internal storage format).  Also falls back
//! to matching by tx_id, so callers can use either identifier.

use axum::{extract::Path, Json};
use serde_json::{json, Value};
use std::collections::HashMap;

use dsm_sdk::storage::client_db::get_transaction_history;

use crate::error::AppError;

/// GET /transaction/:hash
pub async fn get_transaction(Path(hash): Path<String>) -> Result<Json<Value>, AppError> {
    // /transfer returns hex; SDK stores tx_hash as Crockford Base32.
    // Build the base32 equivalent so we can match either way.
    let as_b32 = if hash.len() % 2 == 0 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(&hash)
            .ok()
            .map(|b| dsm_sdk::util::text_id::encode_base32_crockford(&b))
    } else {
        None
    };

    let records = get_transaction_history(None, Some(10_000))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("get_transaction_history: {e}")))?;

    let tx = records.into_iter().find(|r| {
        r.tx_hash == hash
            || r.tx_id == hash
            || as_b32.as_deref().map_or(false, |b| r.tx_hash == b)
    });

    match tx {
        Some(r) => Ok(Json(json!({
            "tx_id":        r.tx_id,
            "tx_hash":      b32_or_hex_to_hex(&r.tx_hash),
            "from_device":  b32_or_hex_to_hex(&r.from_device),
            "to_device":    b32_or_hex_to_hex(&r.to_device),
            "amount":       r.amount,
            "tx_type":      r.tx_type,
            "status":       r.status,
            "chain_height": r.chain_height,
            "memo":         extract_memo(&r.metadata),
        }))),
        None => Err(AppError::NotFound(format!("transaction {hash} not found"))),
    }
}

fn b32_or_hex_to_hex(s: &str) -> String {
    match dsm_sdk::util::text_id::decode_base32_crockford(s) {
        Some(bytes) => hex::encode(&bytes),
        None => s.to_string(),
    }
}

fn extract_memo(metadata: &HashMap<String, Vec<u8>>) -> String {
    metadata
        .get("memo")
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .unwrap_or_default()
}
