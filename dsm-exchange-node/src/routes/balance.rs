// SPDX-License-Identifier: MIT OR Apache-2.0
//! GET /balance?token_id=ERA  →  { token_id, available, locked, symbol, decimals }
//! GET /balances              →  { balances: [...] }

use axum::extract::Query;
use axum::Json;
use prost::Message;
use serde::Deserialize;
use serde_json::{json, Value};

use dsm_sdk::bridge::{AppQuery, AppResult};
use dsm_sdk::generated as pb;

use crate::error::AppError;
use crate::sdk::strip_envelope_prefix;

#[derive(Deserialize)]
pub struct BalanceParams {
    pub token_id: Option<String>,
}

/// GET /balance?token_id=ERA
pub async fn get_balance(Query(params): Query<BalanceParams>) -> Result<Json<Value>, AppError> {
    let token_id = params.token_id.unwrap_or_else(|| "ERA".to_string());
    let balances = fetch_balances_list().await?;
    let entry = balances
        .balances
        .iter()
        .find(|b| b.token_id == token_id)
        .ok_or_else(|| AppError::NotFound(format!("token {token_id} not found")))?;

    Ok(Json(json!({
        "token_id":   entry.token_id,
        "available":  entry.available,
        "locked":     entry.locked,
        "symbol":     entry.symbol,
        "decimals":   entry.decimals,
        "token_name": entry.token_name,
    })))
}

/// GET /balances
pub async fn get_balances() -> Result<Json<Value>, AppError> {
    let balances = fetch_balances_list().await?;
    let list: Vec<Value> = balances
        .balances
        .iter()
        .map(|b| {
            json!({
                "token_id":   b.token_id,
                "available":  b.available,
                "locked":     b.locked,
                "symbol":     b.symbol,
                "decimals":   b.decimals,
                "token_name": b.token_name,
            })
        })
        .collect();
    Ok(Json(json!({ "balances": list })))
}

async fn fetch_balances_list() -> Result<pb::BalancesListResponse, AppError> {
    let router = dsm_sdk::bridge::app_router()
        .ok_or_else(|| AppError::SdkNotReady("app router not installed".to_string()))?;

    // balance.list takes an empty-body ArgPack
    let arg_pack = pb::ArgPack {
        schema_hash: None,
        codec: pb::Codec::Proto as i32,
        body: vec![],
    };
    let mut params = Vec::new();
    arg_pack
        .encode(&mut params)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("encode ArgPack: {e}")))?;

    let result: AppResult = router
        .query(AppQuery {
            path: "balance.list".to_string(),
            params,
        })
        .await;

    if !result.success {
        return Err(AppError::Sdk(
            result
                .error_message
                .unwrap_or_else(|| "balance.list failed".to_string()),
        ));
    }

    // Response is 0x03 + Envelope { payload: BalancesListResponse }
    let data = strip_envelope_prefix(&result.data).map_err(AppError::Internal)?;
    let envelope = pb::Envelope::decode(data.as_slice())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("decode Envelope: {e}")))?;

    match envelope.payload {
        Some(pb::envelope::Payload::BalancesListResponse(resp)) => Ok(resp),
        other => Err(AppError::Internal(anyhow::anyhow!(
            "unexpected envelope payload: {:?}",
            other.map(|p| format!("{p:?}"))
        ))),
    }
}
