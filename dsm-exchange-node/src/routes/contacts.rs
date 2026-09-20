// SPDX-License-Identifier: MIT OR Apache-2.0
//! POST /contacts — add a counterparty as a contact before sending.
//!
//! Body: { "alias": "user1",
//!         "device_id_hex": "<64 hex>",
//!         "genesis_hash_hex": "<64 hex>",
//!         "signing_public_key_hex": "<128 hex>",
//!         "kyber_public_key_hex": "<hex>"   }  ← optional but required for wallet.send

use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use dsm_sdk::bridge::{AppInvoke, AppResult};
use dsm_sdk::storage::client_db::{get_contact_by_device_id, store_contact};

use crate::error::AppError;
use crate::sdk::{make_arg_pack, ContactManualAddRequest};

#[derive(Deserialize)]
pub struct AddContactRequest {
    pub alias: String,
    pub device_id_hex: String,
    pub genesis_hash_hex: String,
    pub signing_public_key_hex: String,
    /// Kyber public key of the counterparty. Required for wallet.send (per-step EK signing).
    /// Obtain from the counterparty's GET /identity response.
    pub kyber_public_key_hex: Option<String>,
}

/// POST /contacts
pub async fn add_contact(Json(req): Json<AddContactRequest>) -> Result<Json<Value>, AppError> {
    let device_id = hex::decode(&req.device_id_hex)
        .map_err(|_| AppError::BadRequest("device_id_hex is not valid hex".to_string()))?;
    let genesis_hash = hex::decode(&req.genesis_hash_hex)
        .map_err(|_| AppError::BadRequest("genesis_hash_hex is not valid hex".to_string()))?;
    let signing_public_key = hex::decode(&req.signing_public_key_hex)
        .map_err(|_| AppError::BadRequest("signing_public_key_hex is not valid hex".to_string()))?;

    if device_id.len() != 32 {
        return Err(AppError::BadRequest("device_id must be 32 bytes".to_string()));
    }
    if genesis_hash.len() != 32 {
        return Err(AppError::BadRequest("genesis_hash must be 32 bytes".to_string()));
    }
    if signing_public_key.len() != 64 {
        return Err(AppError::BadRequest(
            "signing_public_key must be 64 bytes (SPHINCS+ SPX256s)".to_string(),
        ));
    }

    // Decode Kyber key if provided.
    let kyber_public_key = match &req.kyber_public_key_hex {
        Some(hex_str) if !hex_str.is_empty() => {
            hex::decode(hex_str)
                .map_err(|_| AppError::BadRequest("kyber_public_key_hex is not valid hex".to_string()))?
        }
        _ => Vec::new(),
    };

    let msg = ContactManualAddRequest {
        alias: req.alias.clone(),
        device_id: device_id.clone(),
        genesis_hash: genesis_hash.clone(),
        signing_public_key: signing_public_key.clone(),
    };
    let args = make_arg_pack(&msg).map_err(AppError::Internal)?;

    let router = dsm_sdk::bridge::app_router()
        .ok_or_else(|| AppError::SdkNotReady("app router not installed".to_string()))?;

    let result: AppResult = router
        .invoke(AppInvoke {
            method: "contacts.addManual".to_string(),
            args,
        })
        .await;

    if !result.success {
        return Err(AppError::Sdk(
            result
                .error_message
                .unwrap_or_else(|| "contacts.addManual failed".to_string()),
        ));
    }

    // Patch the Kyber public key into the contact record if provided.
    // contacts.addManual doesn't carry a Kyber key field, so we update directly.
    if !kyber_public_key.is_empty() {
        if let Ok(Some(mut contact)) = get_contact_by_device_id(&device_id) {
            contact.kyber_public_key = kyber_public_key;
            if let Err(e) = store_contact(&contact) {
                tracing::warn!("Failed to patch kyber_public_key on contact {}: {e}", req.alias);
            }
        }
    }

    Ok(Json(json!({ "success": true, "alias": req.alias })))
}
