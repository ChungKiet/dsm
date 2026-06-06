// SPDX-License-Identifier: MIT OR Apache-2.0
//! POST /sync — pull pending inbox items and push pending transactions via storage.sync.
//!
//! Calling this endpoint processes any incoming transfers, crediting the balance.

use axum::Json;
use prost::Message;
use serde_json::{json, Value};

use dsm_sdk::bridge::{AppQuery, AppResult};
use dsm_sdk::generated as pb;

use crate::error::AppError;
use crate::sdk::{make_arg_pack, strip_envelope_prefix};

/// POST /sync
pub async fn post_sync() -> Result<Json<Value>, AppError> {
    let req = pb::StorageSyncRequest {
        pull_inbox: true,
        push_pending: true,
        limit: 100,
    };
    let args = make_arg_pack(&req).map_err(AppError::Internal)?;

    let router = dsm_sdk::bridge::app_router()
        .ok_or_else(|| AppError::SdkNotReady("app router not installed".to_string()))?;

    let result: AppResult = router
        .query(AppQuery {
            path: "storage.sync".to_string(),
            params: args,
        })
        .await;

    if !result.success {
        return Err(AppError::Sdk(
            result
                .error_message
                .unwrap_or_else(|| "storage.sync failed".to_string()),
        ));
    }

    let data = strip_envelope_prefix(&result.data).map_err(AppError::Internal)?;
    let envelope = pb::Envelope::decode(data.as_slice())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode Envelope: {e}")))?;

    let resp = match envelope.payload {
        Some(pb::envelope::Payload::StorageSyncResponse(r)) => r,
        other => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "unexpected envelope payload: {:?}",
                other.map(|p| format!("{p:?}"))
            )));
        }
    };

    Ok(Json(json!({
        "success":   resp.success,
        "pulled":    resp.pulled,
        "processed": resp.processed,
        "pushed":    resp.pushed,
        "errors":    resp.errors,
    })))
}
