use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Maximum number of retries when rate-limited (HTTP 429).
const MAX_RETRIES: u32 = 4;
/// Base delay for exponential backoff (doubles each retry: 1s → 2s → 4s → 8s).
const BASE_DELAY_MS: u64 = 1000;

/// Distinguishes auth failures (worth retrying with a fresh session)
/// from other API errors (should be propagated as-is).
#[derive(Debug)]
enum LookupError {
    /// 401/403 — session likely expired, retry after refresh.
    Auth(anyhow::Error),
    /// 429 — rate limited, should back off and retry.
    RateLimited,
    /// Any other failure — do NOT refresh session.
    Other(anyhow::Error),
}

const BASE_URL: &str = "https://calls.okcdn.ru";

// ─── API response types ─────────────────────────────────────────────────────

/// Response from the anonymLogin endpoint.
#[derive(Debug, Deserialize)]
struct AuthResponse {
    session_key: String,
}

/// The nested external_user_id object inside each lookup result.
/// API format: {"id": "<telegram_id>", "ok_anonym": false}
#[derive(Debug, Deserialize)]
struct ExternalUserId {
    id: String,
}

/// A single entry in the lookup response `ids` array.
/// API format: {"ok_user_id": 123, "external_user_id": {"id": "...", "ok_anonym": false}}
#[derive(Debug, Deserialize)]
struct IdEntry {
    external_user_id: ExternalUserId,
}

/// Response from the getOkIdsByExternalIds endpoint.
/// On success: {"ids": [...]}
/// On error/not-found: {"error_code": 4, ...} — parsed with empty `ids` via #[serde(default)]
#[derive(Debug, Deserialize)]
struct LookupResponse {
    #[serde(default)]
    ids: Vec<IdEntry>,
}

// ─── API Client ─────────────────────────────────────────────────────────────

/// HTTP client for the calls.okcdn.ru API.
///
/// Encapsulates:
/// - `reqwest::Client` for HTTP requests
/// - `application_key` for API auth
/// - `session_key` behind an `RwLock` for concurrent read access with exclusive write on refresh
///
/// All requests use `application/x-www-form-urlencoded` via `.form()`.
/// JSON payloads are stringified and passed as form field values.
pub struct ApiClient {
    http: Client,
    application_key: String,
    /// The session key is behind an RwLock because:
    /// - Many handlers read it concurrently (RwLock::read)
    /// - Only one task should refresh it at a time (RwLock::write)
    session_key: RwLock<Option<String>>,
}

impl ApiClient {
    /// Create a new ApiClient with the given application key.
    pub fn new(application_key: String) -> Self {
        Self {
            http: Client::new(),
            application_key,
            session_key: RwLock::new(None),
        }
    }

    /// Authenticate with the API and store the session_key.
    ///
    /// POST https://calls.okcdn.ru/api/auth/anonymLogin
    /// Content-Type: application/x-www-form-urlencoded
    /// Body: application_key=...&session_data={JSON}
    pub async fn authenticate(&self) -> Result<()> {
        let session_data = serde_json::json!({
            "device_id": "telega_checker_bot",
            "version": 2,
            "client_version": "android_8",
            "client_type": "SDK_ANDROID"
        })
        .to_string();

        let form_data = [
            ("application_key", self.application_key.as_str()),
            ("session_data", &session_data),
        ];

        debug!("Authenticating with okcdn.ru API...");

        let resp = self
            .http
            .post(format!("{BASE_URL}/api/auth/anonymLogin"))
            .form(&form_data)
            .send()
            .await
            .context("Failed to send auth request")?;

        let status = resp.status();
        let body = resp.text().await.context("Failed to read auth response body")?;

        if !status.is_success() {
            return Err(anyhow!("Auth failed with status {}: {}", status, body));
        }

        let auth: AuthResponse =
            serde_json::from_str(&body).context("Failed to parse auth response JSON")?;

        // Acquire exclusive write lock to update the session key
        let mut key = self.session_key.write().await;
        *key = Some(auth.session_key.clone());

        info!("Successfully authenticated, session_key acquired");
        Ok(())
    }

    /// Check if a Telegram ID exists in the Telega call infrastructure.
    ///
    /// Wraps [`try_lookup_with_auth`] with an **exponential backoff** retry
    /// loop for HTTP 429 (rate-limited) responses. Retries up to
    /// `MAX_RETRIES` times with delays of 1s → 2s → 4s → 8s.
    pub async fn check_id(&self, telegram_id: i64) -> Result<bool> {
        for attempt in 0..=MAX_RETRIES {
            match self.try_lookup_with_auth(telegram_id).await {
                Ok(found) => return Ok(found),
                Err(LookupError::RateLimited) if attempt < MAX_RETRIES => {
                    let delay = Duration::from_millis(BASE_DELAY_MS * 2u64.pow(attempt));
                    warn!(
                        telegram_id,
                        attempt = attempt + 1,
                        max_retries = MAX_RETRIES,
                        delay_ms = delay.as_millis() as u64,
                        "Rate limited (HTTP 429), backing off..."
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(LookupError::RateLimited) => {
                    return Err(anyhow!(
                        "Rate limited (HTTP 429) for ID {} after {} retries",
                        telegram_id,
                        MAX_RETRIES
                    ));
                }
                Err(LookupError::Auth(e) | LookupError::Other(e)) => return Err(e),
            }
        }

        // Unreachable: the loop always returns, but satisfy the compiler
        unreachable!()
    }

    /// Attempt a lookup with automatic session refresh on auth failure.
    ///
    /// 1. Snapshot the current session key.
    /// 2. Attempt the lookup.
    /// 3. On 401/403, call `refresh_session` (double-checked) and retry once.
    async fn try_lookup_with_auth(
        &self,
        telegram_id: i64,
    ) -> std::result::Result<bool, LookupError> {
        let old_key = self.session_key.read().await.clone();

        match self.try_lookup(telegram_id).await {
            Ok(found) => Ok(found),
            Err(LookupError::Auth(e)) => {
                warn!(
                    "Lookup failed (expired session): {}. Refreshing session_key...",
                    e
                );
                self.refresh_session(old_key)
                    .await
                    .map_err(|e| LookupError::Other(e.context(
                        "Failed to re-authenticate after expired session",
                    )))?;
                // Retry exactly once with the fresh key
                self.try_lookup(telegram_id).await
            }
            // Propagate RateLimited and Other as-is
            Err(e) => Err(e),
        }
    }

    /// Refresh the session key using double-checked locking.
    ///
    /// If another task already refreshed the key (i.e. the current key differs
    /// from `old_key`), this is a no-op — avoids redundant auth API calls.
    async fn refresh_session(&self, old_key: Option<String>) -> Result<()> {
        let mut guard = self.session_key.write().await;

        // Another task already refreshed the key while we were waiting
        if *guard != old_key && guard.is_some() {
            info!("Session key already refreshed by another task, skipping auth");
            return Ok(());
        }

        // We're first — perform the actual auth request
        let session_data = serde_json::json!({
            "device_id": "telega_checker_bot",
            "version": 2,
            "client_version": "android_8",
            "client_type": "SDK_ANDROID"
        })
        .to_string();

        let form_data = [
            ("application_key", self.application_key.as_str()),
            ("session_data", &session_data),
        ];

        debug!("Authenticating with okcdn.ru API (refresh)...");

        let resp = self
            .http
            .post(format!("{BASE_URL}/api/auth/anonymLogin"))
            .form(&form_data)
            .send()
            .await
            .context("Failed to send auth request")?;

        let status = resp.status();
        let body = resp.text().await.context("Failed to read auth response body")?;

        if !status.is_success() {
            return Err(anyhow!("Auth failed with status {}: {}", status, body));
        }

        let auth: AuthResponse =
            serde_json::from_str(&body).context("Failed to parse auth response JSON")?;

        *guard = Some(auth.session_key);
        info!("Successfully refreshed session_key");
        Ok(())
    }

    /// Internal: attempt a single lookup request.
    ///
    /// POST https://calls.okcdn.ru/api/vchat/getOkIdsByExternalIds
    /// Content-Type: application/x-www-form-urlencoded
    /// Body: application_key=...&session_key=...&externalIds=[{JSON}]
    async fn try_lookup(&self, telegram_id: i64) -> std::result::Result<bool, LookupError> {
        // Read the session key without blocking writers longer than needed
        let session_key = {
            let guard = self.session_key.read().await;
            guard
                .clone()
                .ok_or_else(|| {
                    LookupError::Auth(anyhow!("No session_key available — need to authenticate first"))
                })?
        };

        // Build the externalIds JSON array as a string (form-field value)
        let external_ids = serde_json::json!([
            {
                "id": telegram_id.to_string(),
                "ok_anonym": false
            }
        ])
        .to_string();

        let form_data = [
            ("application_key", self.application_key.as_str()),
            ("session_key", session_key.as_str()),
            ("externalIds", external_ids.as_str()),
        ];

        debug!("Looking up Telegram ID {} via API...", telegram_id);

        let resp = self
            .http
            .post(format!("{BASE_URL}/api/vchat/getOkIdsByExternalIds"))
            .form(&form_data)
            .send()
            .await
            .map_err(|e| LookupError::Other(anyhow::Error::from(e).context("Failed to send lookup request")))?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| LookupError::Other(anyhow::Error::from(e).context("Failed to read lookup response body")))?;

        if !status.is_success() {
            // Rate limit — signal the caller to back off and retry
            if status.as_u16() == 429 {
                warn!("Received HTTP 429 (Too Many Requests) from API");
                return Err(LookupError::RateLimited);
            }

            let err = anyhow!("Lookup API returned status {}: {}", status, body);
            // Only treat 401/403 as auth errors worth retrying
            return if status.as_u16() == 401 || status.as_u16() == 403 {
                Err(LookupError::Auth(err))
            } else {
                Err(LookupError::Other(err))
            };
        }

        let lookup: LookupResponse =
            serde_json::from_str(&body)
                .context("Failed to parse lookup response JSON")
                .map_err(LookupError::Other)?;

        // Check if the returned `ids` array contains our target ID
        // Response nests it: {"ids": [{"ok_user_id": ..., "external_user_id": {"id": "TARGET"}}]}
        let target = telegram_id.to_string();
        let found = lookup.ids.iter().any(|entry| entry.external_user_id.id == target);

        debug!(
            "Lookup result for {}: {}",
            telegram_id,
            if found { "FOUND" } else { "NOT FOUND" }
        );

        Ok(found)
    }
}
