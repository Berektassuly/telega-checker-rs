use anyhow::Result;
use sqlx::SqlitePool;
use tracing::info;

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

    // Users who have interacted with the bot (for stats & rate-limiting)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_users (
            user_id    INTEGER PRIMARY KEY,
            username   TEXT,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen  TEXT NOT NULL DEFAULT (datetime('now'))
        )"
    )
    .execute(pool)
    .await?;

    // Optional analytics log of every lookup request
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS requests_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            queried_id INTEGER NOT NULL,
            result     TEXT    NOT NULL,
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
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

/// Record or update a bot user. On conflict, just refresh `last_seen`.
pub async fn log_bot_user(
    pool: &SqlitePool,
    user_id: i64,
    username: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO bot_users (user_id, username)
         VALUES (?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
            username  = excluded.username,
            last_seen = datetime('now')"
    )
    .bind(user_id)
    .bind(username)
    .execute(pool)
    .await?;
    Ok(())
}

// ─── requests_log operations ────────────────────────────────────────────────

/// Insert a lookup event into the analytics log.
pub async fn log_request(
    pool: &SqlitePool,
    user_id: i64,
    queried_id: i64,
    result: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO requests_log (user_id, queried_id, result) VALUES (?, ?, ?)"
    )
    .bind(user_id)
    .bind(queried_id)
    .bind(result)
    .execute(pool)
    .await?;
    Ok(())
}
