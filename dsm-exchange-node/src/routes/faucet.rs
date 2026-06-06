// SPDX-License-Identifier: MIT OR Apache-2.0
//! POST /faucet — claim testnet ERA tokens (local mint, rate-limited by SDK).
//!
//! Uses `faucet.claim` invoke with the exchange's own device_id.
//! Response: { "success": bool, "tokens_received": u64, "new_balance": u64 }

use axum::{extract::State, Json};
use prost::Message;
use serde_json::{json, Value};
use std::sync::Arc;

use dsm_sdk::bridge::{AppInvoke, AppResult};

use crate::error::AppError;
use crate::sdk::make_arg_pack;
use crate::AppState;

/// POST /faucet
pub async fn post_faucet(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let identity_guard = state.identity.read().await;
    let device_id_hex = identity_guard
        .as_ref()
        .map(|id| id.device_id_hex.clone())
        .ok_or_else(|| AppError::SdkNotReady("identity not ready".to_string()))?;
    drop(identity_guard);

    let device_id = hex::decode(&device_id_hex)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode device_id: {e}")))?;

    let req = dsm_sdk::generated::FaucetClaimRequest { device_id };
    let args = make_arg_pack(&req).map_err(AppError::Internal)?;

    let router = dsm_sdk::bridge::app_router()
        .ok_or_else(|| AppError::SdkNotReady("app router not installed".to_string()))?;

    let result: AppResult = router
        .invoke(AppInvoke {
            method: "faucet.claim".to_string(),
            args,
        })
        .await;

    if !result.success {
        return Err(AppError::Sdk(
            result
                .error_message
                .unwrap_or_else(|| "faucet.claim failed".to_string()),
        ));
    }

    // Response: 0x03 + Envelope { payload: FaucetClaimResponse }
    let data = crate::sdk::strip_envelope_prefix(&result.data).map_err(AppError::Internal)?;
    let envelope = dsm_sdk::generated::Envelope::decode(data.as_slice())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode Envelope: {e}")))?;

    let resp = match envelope.payload {
        Some(dsm_sdk::generated::envelope::Payload::FaucetClaimResponse(r)) => r,
        other => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "unexpected envelope payload: {:?}",
                other.map(|p| format!("{p:?}"))
            )));
        }
    };

    Ok(Json(json!({
        "success":         resp.success,
        "tokens_received": resp.tokens_received,
        "message":         resp.message,
    })))
}
