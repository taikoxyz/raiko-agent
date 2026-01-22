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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, middleware, routing::get};
    use axum::body::Body;
    use tower::util::ServiceExt;

    fn state(api_key: Option<&str>) -> AppState {
        AppState {
            registry: crate::ProverRegistry::new(None, None, None),
            rate_limiter: crate::RateLimiter::new(10_000),
            image_manager: crate::ImageManager::new(),
            storage: crate::RequestStorage::new(":memory:".to_string()),
            api_key: api_key.map(|s| s.to_string()),
        }
    }

    async fn ok() -> &'static str {
        "ok"
    }

    #[test]
    fn test_is_exempt_path() {
        assert!(is_exempt_path("/health"));
        assert!(is_exempt_path("/openapi.json"));
        assert!(is_exempt_path("/api-docs/openapi.json"));
        assert!(is_exempt_path("/docs"));
        assert!(is_exempt_path("/scalar"));
        assert!(!is_exempt_path("/proof"));
    }

    #[tokio::test]
    async fn test_exempt_paths_bypass_auth() {
        let state = state(Some("secret"));
        let app = Router::new()
            .route("/health", get(ok))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth::require_api_key,
            ));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_missing_configured_api_key_allows_request() {
        let state = state(None);
        let app = Router::new()
            .route("/proof", get(ok))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth::require_api_key,
            ));

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/proof")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_api_key_header_allows_and_denies() {
        let state = state(Some("secret"));
        let app = Router::new()
            .route("/proof", get(ok))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth::require_api_key,
            ));

        let denied = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/proof")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/proof")
                    .header("x-api-key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_authorization_bearer_allows() {
        let state = state(Some("secret"));
        let app = Router::new()
            .route("/proof", get(ok))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth::require_api_key,
            ));

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/proof")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_options_bypasses_auth() {
        let state = state(Some("secret"));
        let app = Router::new()
            .route("/proof", get(ok))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::auth::require_api_key,
            ));

        let allowed = app
            .oneshot(
                Request::builder()
                    .uri("/proof")
                    .method(Method::OPTIONS)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(allowed.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
