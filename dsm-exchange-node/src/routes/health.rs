// SPDX-License-Identifier: MIT OR Apache-2.0
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

/// GET /health
pub async fn get_health() -> (StatusCode, Json<Value>) {
    let sdk_ready = dsm_sdk::bridge::app_router().is_some();
    let status = if sdk_ready { "ok" } else { "starting" };
    let code = if sdk_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(json!({ "status": status, "sdk_ready": sdk_ready })))
}
