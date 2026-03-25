use anyhow::{Context, Result};

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Telegram bot token (from @BotFather).
    pub bot_token: String,
    /// SQLite database connection URL.
    pub database_url: String,
    /// OK.ru API application key.
    pub application_key: String,
    /// Bearer token for authenticating HTTP API requests (Android plugin).
    pub api_bearer_token: String,
    /// Port for the HTTP API server (default: 8080).
    pub api_port: u16,
    /// Maximum SQLite connection pool size (default: 5).
    /// Increase for deployments with many concurrent group scans.
    pub db_max_connections: u32,
    /// Telegram user ID of the bot administrator.
    /// Required for gating admin-only commands like /upload_assets.
    pub admin_id: i64,
}

impl AppConfig {
    /// Load configuration from environment variables.
    /// Expects `.env` file in the working directory or env vars already set.
    pub fn from_env() -> Result<Self> {
        // Load .env file if present, ignore errors (env vars may already be set)
        let _ = dotenvy::dotenv();

        Ok(Self {
            bot_token: std::env::var("TELOXIDE_TOKEN")
                .context("TELOXIDE_TOKEN must be set")?,
            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL must be set")?,
            application_key: std::env::var("APPLICATION_KEY")
                .unwrap_or_else(|_| "CHKIPMKGDIHBABABA".to_string()),
            api_bearer_token: std::env::var("API_BEARER_TOKEN")
                .context("API_BEARER_TOKEN must be set")?,
            api_port: std::env::var("API_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .context("API_PORT must be a valid port number")?,
            db_max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .context("DATABASE_MAX_CONNECTIONS must be a valid u32")?,
            admin_id: std::env::var("ADMIN_ID")
                .context("ADMIN_ID must be set")?
                .parse()
                .context("ADMIN_ID must be a valid integer (Telegram user ID)")?,
        })
    }
}
