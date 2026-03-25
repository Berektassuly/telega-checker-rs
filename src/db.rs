use anyhow::Result;
use sqlx::SqlitePool;
use tracing::info;
use uuid::Uuid;


// ─── Schema initialization ─────────────────────────────────────────────────

/// Create all required tables if they don't already exist.
pub async fn init_db(pool: &SqlitePool) -> Result<()> {
    // Enable WAL mode for better concurrent read performance
    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(pool)
        .await?;

    // Telegram IDs confirmed to exist in the Telega call infrastructure
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS known_users (
            telegram_id  INTEGER PRIMARY KEY,
            discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"
    )
    .execute(pool)
    .await?;

    // Users who have interacted with the bot (pseudonymized analytics)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_users (
            user_hash  TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen  TEXT NOT NULL DEFAULT (datetime('now'))
        )"
    )
    .execute(pool)
    .await?;

    // Optional analytics log of every lookup request (pseudonymized)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS requests_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_hash  TEXT    NOT NULL,
            queried_id INTEGER NOT NULL,
            result     TEXT    NOT NULL,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )"
    )
    .execute(pool)
    .await?;

    // Chat members: maps users to groups with a soft-delete flag
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS chat_members (
            chat_id   INTEGER NOT NULL,
            user_id   INTEGER NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            PRIMARY KEY (chat_id, user_id)
        )"
    )
    .execute(pool)
    .await?;

    // Per-user API tokens for authenticated HTTP API access
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS api_tokens (
            user_id    INTEGER PRIMARY KEY,
            api_token  TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"
    )
    .execute(pool)
    .await?;

    // Persistent file_id storage for plugin assets
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS plugin_assets (
            name       TEXT PRIMARY KEY,
            file_id    TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"
    )
    .execute(pool)
    .await?;

    info!("Database schema initialized");
    Ok(())
}

// ─── known_users operations ─────────────────────────────────────────────────

/// Check if a Telegram ID is already known to be in the Telega infrastructure.
/// Returns `Some(true)` if found, `None` if not present.
pub async fn check_telega_id(pool: &SqlitePool, telegram_id: i64) -> Result<bool> {
    let row = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM known_users WHERE telegram_id = ? LIMIT 1"
    )
    .bind(telegram_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

/// Persist a confirmed Telega ID into the database.
/// Uses INSERT OR IGNORE to handle duplicates gracefully.
pub async fn save_telega_id(pool: &SqlitePool, telegram_id: i64) -> Result<()> {
    sqlx::query("INSERT OR IGNORE INTO known_users (telegram_id) VALUES (?)")
        .bind(telegram_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── bot_users operations ───────────────────────────────────────────────────

/// Record or update a bot user (pseudonymized). On conflict, just refresh `last_seen`.
pub async fn log_bot_user(
    pool: &SqlitePool,
    user_hash: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO bot_users (user_hash)
         VALUES (?)
         ON CONFLICT(user_hash) DO UPDATE SET
            last_seen = datetime('now')"
    )
    .bind(user_hash)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── requests_log operations ────────────────────────────────────────────────

/// Insert a lookup event into the analytics log (pseudonymized).
pub async fn log_request(
    pool: &SqlitePool,
    user_hash: &str,
    queried_id: i64,
    result: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO requests_log (user_hash, queried_id, result) VALUES (?, ?, ?)"
    )
    .bind(user_hash)
    .bind(queried_id)
    .bind(result)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── chat_members operations ────────────────────────────────────────────────

/// Track a user in a group chat. If the user was previously soft-deleted,
/// re-activate them. Uses INSERT ... ON CONFLICT to avoid duplicates.
pub async fn track_chat_member(pool: &SqlitePool, chat_id: i64, user_id: i64) -> Result<()> {
    sqlx::query(
        "INSERT INTO chat_members (chat_id, user_id, is_active)
         VALUES (?, ?, TRUE)
         ON CONFLICT(chat_id, user_id) DO UPDATE SET is_active = TRUE"
    )
    .bind(chat_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Soft-delete a user from a specific chat (e.g. when they leave the group).
pub async fn untrack_chat_member(pool: &SqlitePool, chat_id: i64, user_id: i64) -> Result<()> {
    sqlx::query(
        "UPDATE chat_members SET is_active = FALSE WHERE chat_id = ? AND user_id = ?"
    )
    .bind(chat_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Soft-delete ALL members for a chat (e.g. when the bot is kicked).
/// Prevents wasting resources on future scans for this chat.
pub async fn deactivate_chat(pool: &SqlitePool, chat_id: i64) -> Result<()> {
    sqlx::query("UPDATE chat_members SET is_active = FALSE WHERE chat_id = ?")
        .bind(chat_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get all distinct chat IDs that have at least one active member.
pub async fn get_active_chat_ids(pool: &SqlitePool) -> Result<Vec<i64>> {
    let rows = sqlx::query_scalar::<_, i64>(
        "SELECT DISTINCT chat_id FROM chat_members WHERE is_active = TRUE"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get all active user IDs for a specific chat.
pub async fn get_active_members(pool: &SqlitePool, chat_id: i64) -> Result<Vec<i64>> {
    let rows = sqlx::query_scalar::<_, i64>(
        "SELECT user_id FROM chat_members WHERE chat_id = ? AND is_active = TRUE"
    )
    .bind(chat_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ─── api_tokens operations ──────────────────────────────────────────────────

/// Get or create a per-user API token. Uses INSERT OR IGNORE so the first
/// call generates a UUID v4, subsequent calls return the existing token.
pub async fn get_or_create_token(pool: &SqlitePool, user_id: i64) -> Result<String> {
    let new_token = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT OR IGNORE INTO api_tokens (user_id, api_token) VALUES (?, ?)"
    )
    .bind(user_id)
    .bind(&new_token)
    .execute(pool)
    .await?;

    let token = sqlx::query_scalar::<_, String>(
        "SELECT api_token FROM api_tokens WHERE user_id = ?"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(token)
}

/// Rotate (replace) a user's API token with a fresh UUID v4.
/// Returns the newly generated token.
pub async fn rotate_token(pool: &SqlitePool, user_id: i64) -> Result<String> {
    let new_token = Uuid::new_v4().to_string();

    sqlx::query(
        "UPDATE api_tokens SET api_token = ?, updated_at = datetime('now') WHERE user_id = ?"
    )
    .bind(&new_token)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(new_token)
}

/// Validate a token from the api_tokens table. Returns true if the token exists.
pub async fn validate_user_token(pool: &SqlitePool, token: &str) -> Result<bool> {
    let row = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM api_tokens WHERE api_token = ? LIMIT 1"
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;

    Ok(row.is_some())
}

// ─── plugin_assets operations ───────────────────────────────────────────────

/// Upsert a plugin asset's file_id. Uses ON CONFLICT to always store
/// the latest file_id for a given asset name.
pub async fn upsert_plugin_asset(pool: &SqlitePool, name: &str, file_id: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO plugin_assets (name, file_id)
         VALUES (?, ?)
         ON CONFLICT(name) DO UPDATE SET
            file_id    = excluded.file_id,
            updated_at = datetime('now')"
    )
    .bind(name)
    .bind(file_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Retrieve all stored plugin assets as (name, file_id) pairs.
pub async fn get_plugin_assets(pool: &SqlitePool) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT name, file_id FROM plugin_assets ORDER BY name"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete a specific plugin asset by name.
pub async fn delete_plugin_asset(pool: &SqlitePool, name: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM plugin_assets WHERE name = ?")
        .bind(name)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}
