// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /identity — returns the exchange's device_id and genesis_hash.
//! POST /genesis — creates genesis on demand (idempotent if already created).

use axum::{extract::State, Json};
use dsm_sdk::sdk::app_state::AppState as SdkAppState;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::error::AppError;
use crate::AppState;

/// GET /identity
pub async fn get_identity(State(state): State<Arc<AppState>>) -> Result<Json<Value>, AppError> {
    let id = state.identity.read().await;
    match &*id {
        Some(identity) => {
            let public_key_hex = SdkAppState::get_public_key()
                .map(|k| hex::encode(&k))
                .unwrap_or_default();
            Ok(Json(json!({
                "device_id":           identity.device_id_hex,
                "genesis_hash":        identity.genesis_hash_hex,
                "signing_public_key":  public_key_hex,
                "kyber_public_key":    identity.kyber_public_key_hex,
            })))
        }
        None => Err(AppError::SdkNotReady(
            "identity not yet created — POST /genesis first".to_string(),
        )),
    }
}
