use axum::{
    Json,
    extract::{Request, State},
    http::{header, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{AppState, api::types::ErrorResponse};

const API_KEY_HEADER: &str = "x-api-key";

fn is_exempt_path(path: &str) -> bool {
    path == "/health"
        || path == "/openapi.json"
        || path.starts_with("/api-docs/")
        || path.starts_with("/docs")
        || path.starts_with("/scalar")
        || path.starts_with("/artifacts/")
        || path.starts_with("/inputs/")
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "Unauthorized".to_string(),
            message: "Missing or invalid API key".to_string(),
        }),
    )
        .into_response()
}

pub async fn require_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS || is_exempt_path(request.uri().path()) {
        return next.run(request).await;
    }

    let expected = match state.api_key() {
        Some(key) => key,
        None => {
            return next.run(request).await;
        }
    };

    let headers = request.headers();
    let mut provided = headers
        .get(API_KEY_HEADER)
        .and_then(|value| value.to_str().ok());

    if provided.is_none() {
        provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                value
                    .strip_prefix("Bearer ")
                    .or_else(|| value.strip_prefix("bearer "))
            });
    }

    if provided == Some(expected) {
        return next.run(request).await;
    }

    unauthorized_response()
}
