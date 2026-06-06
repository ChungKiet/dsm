// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET  /inbox?limit=50  — pull pending b0x messages via the SDK.
//! POST /inbox/ack       — forward acks to every configured storage node.
//!
//! Ack body: { "message_ids_b32": ["<crockford-base32>", ...] }
//! The `id` field returned by GET /inbox items is already Crockford Base32.

use axum::{extract::State, Json};
use prost::Message;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use dsm_sdk::bridge::{AppQuery, AppResult};
use dsm_sdk::generated as pb;

use crate::error::AppError;
use crate::sdk::{make_arg_pack, strip_envelope_prefix, InboxRequest};
use crate::AppState;

#[derive(Deserialize)]
pub struct InboxParams {
    pub limit: Option<u32>,
}

/// GET /inbox
pub async fn get_inbox(
    axum::extract::Query(params): axum::extract::Query<InboxParams>,
) -> Result<Json<Value>, AppError> {
    let limit = params.limit.unwrap_or(50);
    let msg = InboxRequest {
        limit,
        chain_tip: String::new(),
    };
    let args = make_arg_pack(&msg).map_err(AppError::Internal)?;

    let router = dsm_sdk::bridge::app_router()
        .ok_or_else(|| AppError::SdkNotReady("app router not installed".to_string()))?;

    let result: AppResult = router
        .query(AppQuery {
            path: "inbox.pull".to_string(),
            params: args,
        })
        .await;

    if !result.success {
        return Err(AppError::Sdk(
            result
                .error_message
                .unwrap_or_else(|| "inbox.pull failed".to_string()),
        ));
    }

    let data = strip_envelope_prefix(&result.data).map_err(AppError::Internal)?;
    let envelope = pb::Envelope::decode(data.as_slice())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode Envelope: {e}")))?;

    let resp = match envelope.payload {
        Some(pb::envelope::Payload::InboxResponse(r)) => r,
        other => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "unexpected envelope payload: {:?}",
                other.map(|p| format!("{p:?}"))
            )));
        }
    };

    let items: Vec<Value> = resp
        .items
        .iter()
        .map(|item| {
            json!({
                "id":             item.id,
                "preview":        item.preview,
                "tick":           item.tick,
                "sender_id":      item.sender_id,
                "payload_hex":    hex::encode(&item.payload),
                "is_stale_route": item.is_stale_route,
            })
        })
        .collect();

    let count = items.len();
    Ok(Json(json!({ "items": items, "count": count })))
}

#[derive(Deserialize)]
pub struct AckRequest {
    /// Crockford Base32 message IDs — use `items[].id` from GET /inbox.
    pub message_ids_b32: Vec<String>,
}

/// POST /inbox/ack
///
/// Builds a `BatchEnvelope` (each `Envelope.message_id` set to decoded bytes)
/// and POSTs proto bytes to every configured storage node.
/// Partial node failures are logged but don't fail the overall response.
pub async fn post_inbox_ack(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AckRequest>,
) -> Result<Json<Value>, AppError> {
    if req.message_ids_b32.is_empty() {
        return Ok(Json(json!({ "acked": 0 })));
    }

    // Decode Base32 → raw bytes and build sparse Envelope stubs (only message_id set)
    let mut envelopes = Vec::with_capacity(req.message_ids_b32.len());
    for id_b32 in &req.message_ids_b32 {
        let bytes =
            dsm_sdk::util::text_id::decode_base32_crockford(id_b32).ok_or_else(|| {
                AppError::BadRequest(format!(
                    "message_id is not valid Crockford Base32: {id_b32}"
                ))
            })?;
        envelopes.push(pb::Envelope {
            message_id: bytes,
            ..Default::default()
        });
    }

    let batch = pb::BatchEnvelope {
        envelopes,
        batch_signature: vec![],
        atomic_execution: false,
    };
    let mut body_bytes = Vec::new();
    batch
        .encode(&mut body_bytes)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("encode BatchEnvelope: {e}")))?;

    // Auth header: "DSM <device_b32>:" (token part left empty for ack)
    let identity_guard = state.identity.read().await;
    let device_id_hex = identity_guard
        .as_ref()
        .map(|id| id.device_id_hex.clone())
        .ok_or_else(|| AppError::SdkNotReady("identity not ready".to_string()))?;
    drop(identity_guard);

    let device_id_bytes = hex::decode(&device_id_hex)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode device_id hex: {e}")))?;
    let device_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&device_id_bytes);

    let client = reqwest::Client::new();
    let mut acked_nodes = 0usize;
    for endpoint in &state.config.storage.endpoints {
        let url = format!("{}/api/v2/b0x/ack", endpoint.trim_end_matches('/'));
        match client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", format!("DSM {}:", device_b32))
            .body(body_bytes.clone())
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 204 => {
                acked_nodes += 1;
            }
            Ok(resp) => {
                tracing::warn!("b0x ack to {url} returned {}", resp.status());
            }
            Err(e) => {
                tracing::warn!("b0x ack to {url} failed: {e}");
            }
        }
    }

    Ok(Json(json!({
        "acked":       req.message_ids_b32.len(),
        "acked_nodes": acked_nodes,
        "total_nodes": state.config.storage.endpoints.len(),
    })))
}
