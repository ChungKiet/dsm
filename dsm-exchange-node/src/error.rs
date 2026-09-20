// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unified error type that converts to axum JSON responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("SDK not ready: {0}")]
    SdkNotReady(String),

    #[error("SDK error: {0}")]
    Sdk(String),

    #[error("internal: {0}")]
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::SdkNotReady(m) => (StatusCode::SERVICE_UNAVAILABLE, m.clone()),
            AppError::Sdk(m) => (StatusCode::UNPROCESSABLE_ENTITY, m.clone()),
            AppError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
