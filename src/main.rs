mod api_client;
mod bot_handler;
mod config;
mod db;
mod scheduler;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use moka::future::Cache;
use sqlx::sqlite::SqlitePoolOptions;
use teloxide::prelude::*;
use tracing::info;

use bot_handler::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Initialize logging ──
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting TelegaChecker bot...");

    // ── Load configuration ──
    let cfg = config::AppConfig::from_env().context("Failed to load configuration")?;

    // ── Initialize SQLite connection pool ──
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&cfg.database_url)
        .await
        .context("Failed to connect to SQLite database")?;

    // Run schema migrations
    db::init_db(&pool)
        .await
        .context("Failed to initialize database schema")?;

    // ── Initialize moka in-memory cache ──
    //
    // We use a single Cache<i64, bool> where:
    //   true  = ID exists in Telega (positive cache)
    //   false = ID not found (negative cache)
    //
    // TTL is set to 24 hours for all entries. Positive entries are also
    // persisted to SQLite, so even after cache eviction they'll be found
    // on the next lookup (Layer 2). Negative entries only live in cache
    // to prevent repeated API calls for non-existent IDs.
    //
    // Max capacity is set to 100_000 entries. LRU eviction kicks in
    // when this limit is reached, removing the least-recently-used entries.
    let cache: Cache<i64, bool> = Cache::builder()
        .max_capacity(100_000)
        .time_to_live(Duration::from_secs(24 * 60 * 60)) // 24 hours
        .build();

    // ── Initialize tracking dedup cache ──
    // Short TTL (5 minutes) to deduplicate (chat_id, user_id) pairs
    // and avoid hitting the database on every message in active groups.
    let tracking_cache: Cache<(i64, i64), ()> = Cache::builder()
        .max_capacity(50_000)
        .time_to_live(Duration::from_secs(5 * 60)) // 5 minutes
        .build();

    // ── Initialize API client & perform initial authentication ──
    let api = Arc::new(api_client::ApiClient::new(cfg.application_key.clone()));
    api.authenticate()
        .await
        .context("Failed initial authentication with okcdn.ru")?;

    // ── Build shared state ──
    let state = AppState {
        pool,
        cache,
        api,
        tracking_cache,
    };

    // ── Setup teloxide bot & dispatcher ──
    let bot = Bot::new(&cfg.bot_token);
    info!("Bot connected. Setting up handlers...");

    // ── Start the daily scan scheduler ──
    scheduler::start_daily_scan(bot.clone(), state.clone())
        .await
        .context("Failed to start daily scan scheduler")?;

    let handler = dptree::entry()
        // Handle /start command
        .branch(
            Update::filter_message()
                .filter_command::<BotCommands>()
                .endpoint(commands_handler),
        )
        // Handle new chat members joining groups
        .branch(
            Update::filter_message()
                .filter(|msg: Message| msg.new_chat_members().is_some())
                .endpoint(bot_handler::handle_new_chat_members),
        )
        // Handle member leaving a group
        .branch(
            Update::filter_message()
                .filter(|msg: Message| msg.left_chat_member().is_some())
                .endpoint(bot_handler::handle_left_chat_member),
        )
        // Passively track users who send messages in groups
        .branch(
            Update::filter_message()
                .filter(bot_handler::is_group_chat)
                .endpoint(bot_handler::handle_group_message),
        )
        // Handle plain text messages (ID lookups) — private chats only
        .branch(
            Update::filter_message()
                .filter(bot_handler::is_private_chat)
                .endpoint(bot_handler::handle_message),
        )
        // Handle inline queries
        .branch(
            Update::filter_inline_query().endpoint(bot_handler::handle_inline_query),
        );

    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![state])
        .default_handler(|upd| async move {
            tracing::debug!("Unhandled update: {:?}", upd);
        })
        .error_handler(LoggingErrorHandler::with_custom_text(
            "Error in the dispatcher",
        ))
        .enable_ctrlc_handler()
        .build()
        .dispatch()
        .await;

    info!("Bot stopped.");
    Ok(())
}

// ─── Command definitions ────────────────────────────────────────────────────

#[derive(teloxide::macros::BotCommands, Clone)]
#[command(rename_rule = "lowercase")]
enum BotCommands {
    /// Start the bot / show help
    Start,
}

/// Route commands to their respective handlers.
async fn commands_handler(
    bot: Bot,
    msg: Message,
    cmd: BotCommands,
) -> Result<(), teloxide::RequestError> {
    match cmd {
        BotCommands::Start => bot_handler::handle_start(bot, msg).await,
    }
}
