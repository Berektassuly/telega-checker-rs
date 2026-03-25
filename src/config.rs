use anyhow::{Context, Result};
use tracing::info;
use uuid::Uuid;

/// Filename for the auto-generated analytics pepper.
const ANALYTICS_KEY_FILENAME: &str = ".analytics_key";

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
    /// Secret pepper for HMAC-SHA256 pseudonymization of analytics user IDs.
    /// Auto-generated on first startup and persisted alongside the database.
    pub analytics_salt: String,
}

impl AppConfig {
    /// Load configuration from environment variables.
    /// Expects `.env` file in the working directory or env vars already set.
    pub fn from_env() -> Result<Self> {
        // Load .env file if present, ignore errors (env vars may already be set)
        let _ = dotenvy::dotenv();

        let database_url = std::env::var("DATABASE_URL")
            .context("DATABASE_URL must be set")?;

        Ok(Self {
            bot_token: std::env::var("TELOXIDE_TOKEN")
                .context("TELOXIDE_TOKEN must be set")?,
            analytics_salt: Self::load_or_generate_salt(&database_url)
                .context("Failed to load or generate analytics salt")?,
            database_url,
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

    /// Load the analytics pepper from `.analytics_key`, or generate a new one
    /// using two concatenated UUID v4 values (zero-knowledge approach).
    ///
    /// The key file is placed in the same directory as the SQLite database,
    /// which is guaranteed to be writable (important for Docker volume mounts).
    fn load_or_generate_salt(database_url: &str) -> Result<String> {
        let key_path = Self::analytics_key_path(database_url);

        if key_path.exists() {
            let key = std::fs::read_to_string(&key_path)
                .context("Failed to read .analytics_key")?
                .trim()
                .to_string();
            info!("Analytics salt loaded from {}", key_path.display());
            return Ok(key);
        }

        // Generate a strong key: two UUID v4 concatenated (72 chars of entropy)
        let key = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
        std::fs::write(&key_path, &key).context("Failed to write .analytics_key")?;
        info!("Generated new analytics salt and saved to {}", key_path.display());
        Ok(key)
    }

    /// Derive the `.analytics_key` file path from the DATABASE_URL.
    /// Places it in the same directory as the SQLite database file,
    /// falling back to the current directory if parsing fails.
    fn analytics_key_path(database_url: &str) -> std::path::PathBuf {
        // DATABASE_URL format: "sqlite:/app/data/telega_checker.db?mode=rwc"
        // Strip the "sqlite:" prefix and any query parameters
        let db_file = database_url
            .strip_prefix("sqlite:")
            .unwrap_or(database_url)
            .split('?')
            .next()
            .unwrap_or(database_url);

        let db_path = std::path::Path::new(db_file);
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                return parent.join(ANALYTICS_KEY_FILENAME);
            }
        }

        // Fallback: current directory
        std::path::PathBuf::from(ANALYTICS_KEY_FILENAME)
    }
}
