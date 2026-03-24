use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

const BASE_URL: &str = "https://calls.okcdn.ru";

// ─── API response types ─────────────────────────────────────────────────────

/// Response from the anonymLogin endpoint.
#[derive(Debug, Deserialize)]
struct AuthResponse {
    session_key: String,
}

/// A single ID entry returned by the lookup endpoint.
#[derive(Debug, Deserialize)]
struct IdEntry {
    id: String,
}

/// Response from the getOkIdsByExternalIds endpoint.
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
    /// This method implements a **retry-on-expired-session** pattern:
    /// 1. Acquire a read lock on session_key and attempt the lookup.
    /// 2. If the API returns an auth error (or session_key is missing),
    ///    call `authenticate()` to refresh the key and retry ONCE.
    /// 3. This prevents infinite retry loops while handling legitimate expiration.
    pub async fn check_id(&self, telegram_id: i64) -> Result<bool> {
        // First attempt — use existing session key (or authenticate if none)
        match self.try_lookup(telegram_id).await {
            Ok(found) => Ok(found),
            Err(e) => {
                warn!(
                    "Lookup failed (likely expired session): {}. Refreshing session_key...",
                    e
                );
                // Refresh the session key
                self.authenticate().await.context(
                    "Failed to re-authenticate after expired session",
                )?;
                // Retry exactly once with the fresh key
                self.try_lookup(telegram_id)
                    .await
                    .context("Lookup failed even after session refresh")
            }
        }
    }

    /// Internal: attempt a single lookup request.
    ///
    /// POST https://calls.okcdn.ru/api/vchat/getOkIdsByExternalIds
    /// Content-Type: application/x-www-form-urlencoded
    /// Body: application_key=...&session_key=...&externalIds=[{JSON}]
    async fn try_lookup(&self, telegram_id: i64) -> Result<bool> {
        // Read the session key without blocking writers longer than needed
        let session_key = {
            let guard = self.session_key.read().await;
            guard
                .clone()
                .ok_or_else(|| anyhow!("No session_key available — need to authenticate first"))?
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
            .context("Failed to send lookup request")?;

        let status = resp.status();
        let body = resp.text().await.context("Failed to read lookup response body")?;

        // Treat non-2xx as a potential auth/session error to trigger retry
        if !status.is_success() {
            return Err(anyhow!(
                "Lookup API returned status {}: {}",
                status,
                body
            ));
        }

        let lookup: LookupResponse =
            serde_json::from_str(&body).context("Failed to parse lookup response JSON")?;

        // Check if the returned `ids` array contains our target ID
        let target = telegram_id.to_string();
        let found = lookup.ids.iter().any(|entry| entry.id == target);

        debug!(
            "Lookup result for {}: {}",
            telegram_id,
            if found { "FOUND" } else { "NOT FOUND" }
        );

        Ok(found)
    }
}
