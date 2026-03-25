use std::net::SocketAddr;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::bot_handler::{check_user, AppState};

// ─── API response types ─────────────────────────────────────────────────────

/// JSON response returned by the `/api/check/:telegram_id` endpoint.
#[derive(Serialize)]
struct CheckResponse {
    telegram_id: i64,
    is_compromised: bool,
}

/// JSON error body for API error responses.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ─── Shared state for Axum ──────────────────────────────────────────────────

/// State shared across all Axum handlers.
/// Holds the reused `AppState` (cache, DB pool, API client) plus the
/// expected bearer token for authentication.
#[derive(Clone)]
pub struct ApiState {
    pub app_state: AppState,
    pub bearer_token: String,
}

// ─── Bearer token validation ────────────────────────────────────────────────

/// Extract and validate the `Authorization: Bearer <TOKEN>` header.
/// Returns `401 Unauthorized` if the header is missing or doesn't match.
fn validate_bearer(headers: &HeaderMap, expected_token: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Missing Authorization header".to_string(),
                }),
            )
        })?;

    // Expect format: "Bearer <token>"
    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid Authorization format. Expected: Bearer <token>".to_string(),
            }),
        )
    })?;

    if token != expected_token {
        warn!("API request rejected: invalid bearer token");
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid bearer token".to_string(),
            }),
        ));
    }

    Ok(())
}

// ─── Endpoint handlers ──────────────────────────────────────────────────────

/// `GET /api/check/:telegram_id`
///
/// Performs the same 3-tier lookup (moka cache → SQLite → external API)
/// as the Telegram bot, reusing the shared `AppState`.
async fn handle_check(
    State(api_state): State<ApiState>,
    headers: HeaderMap,
    Path(telegram_id_str): Path<String>,
) -> impl IntoResponse {
    // ── Authenticate ──
    validate_bearer(&headers, &api_state.bearer_token)?;

    // ── Parse the telegram_id ──
    let telegram_id: i64 = match telegram_id_str.parse() {
        Ok(id) if id > 0 => id,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Invalid telegram_id '{}'. Must be a positive integer.",
                        telegram_id_str
                    ),
                }),
            ));
        }
    };

    info!(telegram_id, "API lookup request");

    // ── Run the 3-tier lookup (L1 cache → L2 SQLite → L3 API) ──
    match check_user(telegram_id, &api_state.app_state).await {
        Ok(is_compromised) => {
            info!(telegram_id, is_compromised, "API lookup complete");
            Ok(Json(CheckResponse {
                telegram_id,
                is_compromised,
            }))
        }
        Err(e) => {
            error!(telegram_id, error = %e, "API lookup failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal lookup error. Please try again later.".to_string(),
                }),
            ))
        }
    }
}

// ─── Router & server ────────────────────────────────────────────────────────

/// Build the Axum router with all API endpoints.
fn build_router(api_state: ApiState) -> Router {
    Router::new()
        .route("/api/check/{telegram_id}", get(handle_check))
        .with_state(api_state)
}

/// Start the Axum HTTP API server.
///
/// Binds to `0.0.0.0:{port}` and serves until a shutdown signal is received.
/// This function is designed to be run concurrently alongside the Teloxide bot
/// via `tokio::select!`.
pub async fn run_api_server(
    app_state: AppState,
    bearer_token: String,
    port: u16,
) -> anyhow::Result<()> {
    let api_state = ApiState {
        app_state,
        bearer_token,
    };

    let router = build_router(api_state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    info!(%addr, "HTTP API server listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("HTTP API server stopped");
    Ok(())
}

/// Wait for SIGTERM or Ctrl+C to trigger graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => info!("Received Ctrl+C, shutting down API server..."),
            _ = sigterm.recv() => info!("Received SIGTERM, shutting down API server..."),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("Failed to listen for Ctrl+C");
        info!("Received Ctrl+C, shutting down API server...");
    }
}
