mod api_client;
mod api_server;
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
use teloxide::types::UserId;
use tracing::{error, info};

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

    info!("Starting TelegaChecker (Dual-Core: Bot + API)...");

    // ── Load configuration ──
    let cfg = config::AppConfig::from_env().context("Failed to load configuration")?;

    // ── Initialize SQLite connection pool ──
    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.db_max_connections)
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
    // AppState is Clone-friendly: SqlitePool, Cache, and Arc<ApiClient>
    // all use internal Arc. Both the bot and HTTP server get zero-cost access.
    let state = AppState {
        pool,
        cache,
        api,
        tracking_cache,
        admin_id: cfg.admin_id,
    };

    // ── Setup teloxide bot & dispatcher ──
    let bot = Bot::new(&cfg.bot_token);
    info!("Bot connected. Setting up handlers...");

    // ── Start the daily scan scheduler ──
    let mut scheduler_handle = scheduler::start_daily_scan(bot.clone(), state.clone())
        .await
        .context("Failed to start daily scan scheduler")?;

    // ── Admin user ID for dispatcher-level filtering ──
    let admin_user_id = UserId(cfg.admin_id as u64);

    let handler = dptree::entry()
        // ── All message-based handlers under a single filter_message ──
        .branch(
            Update::filter_message()
                // /start command (highest priority)
                .branch(
                    dptree::entry()
                        .filter_command::<BotCommands>()
                        .endpoint(commands_handler),
                )
                // /upload_assets — admin only (filtered at dispatcher level)
                .branch(
                    dptree::entry()
                        .filter_command::<AdminCommands>()
                        .filter(move |msg: Message| {
                            msg.from
                                .as_ref()
                                .map(|u| u.id == admin_user_id)
                                .unwrap_or(false)
                        })
                        .endpoint(admin_commands_handler),
                )
                // New chat members joining groups
                .branch(
                    dptree::filter_map(|msg: Message| {
                        if msg.new_chat_members().is_some() {
                            Some(msg)
                        } else {
                            None
                        }
                    })
                    .endpoint(bot_handler::handle_new_chat_members),
                )
                // Member leaving a group
                .branch(
                    dptree::filter_map(|msg: Message| {
                        if msg.left_chat_member().is_some() {
                            Some(msg)
                        } else {
                            None
                        }
                    })
                    .endpoint(bot_handler::handle_left_chat_member),
                )
                // Mention lookup in groups: @bot_username <id>
                .branch(
                    dptree::filter_map(|msg: Message| {
                        if bot_handler::is_group_chat(&msg) {
                            if let Some(text) = msg.text() {
                                if text.starts_with('@') {
                                    return Some(msg);
                                }
                            }
                        }
                        None
                    })
                    .endpoint(bot_handler::handle_mention_lookup),
                )
                // Passively track users who send messages in groups
                .branch(
                    dptree::filter_map(|msg: Message| {
                        if bot_handler::is_group_chat(&msg) {
                            Some(msg)
                        } else {
                            None
                        }
                    })
                    .endpoint(bot_handler::handle_group_message),
                )
                // Plain text messages (ID lookups) — private chats only
                .branch(
                    dptree::filter_map(|msg: Message| {
                        if bot_handler::is_private_chat(&msg) {
                            Some(msg)
                        } else {
                            None
                        }
                    })
                    .endpoint(bot_handler::handle_message),
                ),
        )
        // ── Callback queries (inline button presses) ──
        .branch(
            Update::filter_callback_query().endpoint(bot_handler::handle_callback_query),
        )
        // ── Inline queries ──
        .branch(
            Update::filter_inline_query().endpoint(bot_handler::handle_inline_query),
        );

    let mut dispatcher = Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![state.clone()])
        .default_handler(|upd| async move {
            tracing::debug!("Unhandled update: {:?}", upd);
        })
        .error_handler(LoggingErrorHandler::with_custom_text(
            "Error in the dispatcher",
        ))

        .build();

    // ── Run both cores concurrently ──
    // tokio::select! races the HTTP API server and the Telegram bot dispatcher.
    // When either finishes (e.g. on SIGTERM/Ctrl+C), the other is cancelled.
    let api_bearer_token = cfg.api_bearer_token.clone();
    let api_port = cfg.api_port;
    let api_state = state.clone();

    info!("Starting Dual-Core: Telegram Bot + HTTP API on port {}", api_port);

    tokio::select! {
        result = api_server::run_api_server(api_state, api_bearer_token, api_port) => {
            match result {
                Ok(()) => info!("HTTP API server exited gracefully"),
                Err(e) => error!("HTTP API server error: {}", e),
            }
        }
        () = dispatcher.dispatch() => {
            info!("Telegram bot dispatcher exited");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, initiating graceful shutdown...");
        }
    }

    // Gracefully shut down the daily scan scheduler
    info!("Shutting down scheduler...");
    if let Err(e) = scheduler_handle.shutdown().await {
        error!("Failed to shut down scheduler: {}", e);
    }

    info!("TelegaChecker stopped.");
    Ok(())
}

// ─── Command definitions ────────────────────────────────────────────────────

#[derive(teloxide::macros::BotCommands, Clone)]
#[command(rename_rule = "lowercase")]
enum BotCommands {
    /// Start the bot / show help
    Start,
    /// Download plugins and get API key
    Plugins,
}

#[derive(teloxide::macros::BotCommands, Clone)]
#[command(rename_rule = "snake_case")]
enum AdminCommands {
    /// Upload plugin assets (admin only)
    UploadAssets,
}

/// Route user commands to their respective handlers.
async fn commands_handler(
    bot: Bot,
    msg: Message,
    cmd: BotCommands,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    match cmd {
        BotCommands::Start => bot_handler::handle_start(bot, msg).await,
        BotCommands::Plugins => bot_handler::handle_plugins(bot, msg, state).await,
    }
}

/// Route admin commands to their respective handlers.
async fn admin_commands_handler(
    bot: Bot,
    msg: Message,
    cmd: AdminCommands,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    match cmd {
        AdminCommands::UploadAssets => bot_handler::handle_upload_assets(bot, msg, state).await,
    }
}
