// SPDX-License-Identifier: MIT OR Apache-2.0
//! POST /transfer — online ERA transfer via b0x.
//!
//! Body: { "to_device_id_hex": "<64 hex>", "amount": 1000, "token_id": "ERA", "memo": "..." }
//!
//! Uses `wallet.sendSmart` — accepts decimal-amount strings and resolves the
//! recipient by Crockford Base32 device ID.  SPHINCS+ signing, nonce, and seq
//! are handled internally by the SDK.
//!
//! NOTE: recipient MUST be added via POST /contacts before sending.

use axum::Json;
use prost::Message;
use serde::Deserialize;
use serde_json::{json, Value};

use dsm_sdk::bridge::{AppInvoke, AppResult};
use dsm_sdk::generated as pb;

use crate::error::AppError;
use crate::sdk::{make_arg_pack, strip_envelope_prefix, OnlineTransferSmartRequest};

#[derive(Deserialize)]
pub struct TransferRequest {
    /// 64 hex chars — recipient's device_id.
    pub to_device_id_hex: String,
    /// Integer token amount (ERA has 0 decimals).
    pub amount: u64,
    /// Token ID, defaults to "ERA"
    pub token_id: Option<String>,
    /// Optional memo
    pub memo: Option<String>,
}

/// POST /transfer
pub async fn post_transfer(Json(req): Json<TransferRequest>) -> Result<Json<Value>, AppError> {
    let device_id_bytes = hex::decode(&req.to_device_id_hex)
        .map_err(|_| AppError::BadRequest("to_device_id_hex is not valid hex".to_string()))?;
    if device_id_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "to_device_id_hex must decode to exactly 32 bytes".to_string(),
        ));
    }

    // wallet.sendSmart accepts Crockford Base32 recipient
    let recipient_b32 =
        dsm_sdk::util::text_id::encode_base32_crockford(&device_id_bytes);

    let msg = OnlineTransferSmartRequest {
        recipient: recipient_b32,
        amount: req.amount.to_string(),
        token_id: req.token_id.unwrap_or_else(|| "ERA".to_string()),
        memo: req.memo.unwrap_or_default(),
    };
    let args = make_arg_pack(&msg).map_err(AppError::Internal)?;

    let router = dsm_sdk::bridge::app_router()
        .ok_or_else(|| AppError::SdkNotReady("app router not installed".to_string()))?;

    let result: AppResult = router
        .invoke(AppInvoke {
            method: "wallet.sendSmart".to_string(),
            args,
        })
        .await;

    if !result.success {
        return Err(AppError::Sdk(
            result
                .error_message
                .unwrap_or_else(|| "wallet.sendSmart failed".to_string()),
        ));
    }

    let data = strip_envelope_prefix(&result.data).map_err(AppError::Internal)?;
    let envelope = pb::Envelope::decode(data.as_slice())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode Envelope: {e}")))?;

    let resp = match envelope.payload {
        Some(pb::envelope::Payload::OnlineTransferResponse(r)) => r,
        other => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "unexpected envelope payload: {:?}",
                other.map(|p| format!("{p:?}"))
            )));
        }
    };

    let online_tx = dsm_sdk::storage::client_db::get_transaction_history(None, Some(10_000))
        .ok()
        .and_then(|txs| txs.into_iter().find(|r| r.tx_type == "online"));

    let (tx_id, tx_hash_db) = match online_tx {
        Some(ref r) => (
            r.tx_id.clone(),
            crate::routes::block::b32_or_hex_to_hex(&r.tx_hash),
        ),
        None => (String::new(), String::new()),
    };

    Ok(Json(json!({
        "success":     resp.success,
        "message":     resp.message,
        "new_balance": resp.new_balance,
        "tx_hash":     tx_hash_db,
        "tx_id":       tx_id,
    })))
}
