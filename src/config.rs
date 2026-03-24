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
        })
    }
}
