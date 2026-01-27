use axum::{
    Json,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{AppState, api::types::ErrorResponse};

const API_KEY_HEADER: &str = "x-api-key";
const ALLOW_UNAUTHENTICATED_ENV: &str = "ALLOW_UNAUTHENTICATED";

fn is_exempt_path(path: &str) -> bool {
    path == "/health"
        || path == "/openapi.json"
        || path.starts_with("/api-docs/")
        || path.starts_with("/docs")
        || path.starts_with("/scalar")
}

fn is_destructive_request(method: &Method, path: &str) -> bool {
    method == Method::DELETE && path == "/requests"
}

fn allow_unauthenticated() -> bool {
    std::env::var(ALLOW_UNAUTHENTICATED_ENV)
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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
            if is_destructive_request(request.method(), request.uri().path())
                && !allow_unauthenticated()
            {
                return unauthorized_response();
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        routing::{delete, get},
    };
    use tower::util::ServiceExt;

    fn build_state(api_key: Option<String>) -> AppState {
        let image_manager = crate::ImageManager::new();
        let storage = crate::RequestStorage::new("test_auth.db".to_string());
        let registry = crate::ProverRegistry::new(None, None, None);
        AppState {
            registry,
            rate_limiter: crate::RateLimiter::new(0),
            image_manager,
            storage,
            api_key,
        }
    }

    #[tokio::test]
    async fn delete_requests_requires_key_even_when_unset() {
        let state = build_state(None);
        let app = Router::new()
            .route("/requests", delete(|| async { StatusCode::OK }))
            .route("/health", get(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(state, require_api_key));

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/requests")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
