use std::sync::Arc;

use anyhow::Result;
use moka::future::Cache;
use sqlx::SqlitePool;
use teloxide::prelude::*;
use teloxide::types::{
    InlineQueryResult, InlineQueryResultArticle, InputMessageContent,
    InputMessageContentText,
};
use tracing::{error, info};

use crate::api_client::ApiClient;
use crate::db;

/// Shared application state injected into all handlers via `dptree::deps!`.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    /// Single cache mapping Telegram ID → exists (true/false).
    /// - Positive entries (true): long TTL (populated from API hits or DB).
    /// - Negative entries (false): shorter TTL to avoid permanent false negatives.
    pub cache: Cache<i64, bool>,
    pub api: Arc<ApiClient>,
}

// ─── Core lookup logic ──────────────────────────────────────────────────────

/// Three-tier lookup: moka cache → SQLite → okcdn.ru API.
///
/// Flow:
/// 1. Check in-memory cache (instant, no I/O).
/// 2. If cache miss, check SQLite (fast local I/O).
///    - If found in DB, populate cache and return.
/// 3. If DB miss, hit the upstream API.
///    - Save positive results to both DB and cache.
///    - Save negative results to cache only (with shorter TTL via cache policy).
async fn check_user(telegram_id: i64, state: &AppState) -> Result<bool> {
    // ── Layer 1: In-memory cache (moka) ──
    if let Some(cached) = state.cache.get(&telegram_id).await {
        info!("Cache HIT for ID {}: {}", telegram_id, cached);
        return Ok(cached);
    }

    // ── Layer 2: SQLite persistent storage ──
    let in_db = db::check_telega_id(&state.pool, telegram_id).await?;
    if in_db {
        info!("DB HIT for ID {}", telegram_id);
        // Populate cache with positive result
        state.cache.insert(telegram_id, true).await;
        return Ok(true);
    }

    // ── Layer 3: Upstream API call ──
    info!("Cache & DB MISS for ID {}. Querying API...", telegram_id);
    let found = state.api.check_id(telegram_id).await?;

    if found {
        // Persist positive results to both DB and cache
        db::save_telega_id(&state.pool, telegram_id).await?;
        state.cache.insert(telegram_id, true).await;
    } else {
        // Cache negative results (cache TTL handles expiration)
        state.cache.insert(telegram_id, false).await;
    }

    Ok(found)
}

// ─── /start command handler ─────────────────────────────────────────────────

/// Handle the /start command with a greeting message.
pub async fn handle_start(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let greeting = concat!(
        "👋 Привет\\! Я — *TelegaChecker*\\.\n\n",
        "Отправь мне Telegram ID \\(числом\\), и я проверю, ",
        "зарегистрирован ли он в приложении Telega\\.\n\n",
        "Ответ будет: *ДА* или *НЕТ*\\.\n\n",
        "Также можешь использовать инлайн\\-режим: ",
        "`@имя\\_бота 12345`",
    );

    bot.send_message(msg.chat.id, greeting)
        .parse_mode(teloxide::types::ParseMode::MarkdownV2)
        .await?;

    Ok(())
}

// ─── Text message handler ───────────────────────────────────────────────────

/// Handle plain text messages. Expects a numeric Telegram ID.
pub async fn handle_message(
    bot: Bot,
    msg: Message,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    let text = match msg.text() {
        Some(t) => t.trim(),
        None => return Ok(()),
    };

    // Skip messages starting with '/' (commands are handled separately)
    if text.starts_with('/') {
        return Ok(());
    }

    // Validate: input must be digits only
    let telegram_id: i64 = match text.parse() {
        Ok(id) if id > 0 => id,
        _ => {
            bot.send_message(
                msg.chat.id,
                "⚠️ Пожалуйста, отправь корректный Telegram ID (только цифры).",
            )
            .await?;
            return Ok(());
        }
    };

    // Log the bot user (fire-and-forget, don't block the response)
    let user_id = msg.from.as_ref().map(|u| u.id.0 as i64).unwrap_or(0);
    let username = msg.from.as_ref().and_then(|u| u.username.as_deref());
    if let Err(e) = db::log_bot_user(&state.pool, user_id, username).await {
        error!("Failed to log bot user: {}", e);
    }

    // Run the three-tier lookup
    let (reply_text, result_short) = match check_user(telegram_id, &state).await {
        Ok(true) => ("✅ ДА — этот ID зарегистрирован в Telega.", "YES"),
        Ok(false) => ("❌ НЕТ — этот ID не найден в Telega.", "NO"),
        Err(e) => {
            error!("Lookup error for ID {}: {}", telegram_id, e);
            (
                "⚠️ Произошла ошибка при проверке. Попробуйте позже.",
                "ERROR",
            )
        }
    };

    // Log the request
    if let Err(e) = db::log_request(&state.pool, user_id, telegram_id, result_short).await {
        error!("Failed to log request: {}", e);
    }

    bot.send_message(msg.chat.id, reply_text).await?;

    Ok(())
}

// ─── Inline query handler ───────────────────────────────────────────────────

/// Handle inline queries: @bot_name <telegram_id>
pub async fn handle_inline_query(
    bot: Bot,
    q: InlineQuery,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    let input = q.query.trim();

    // Validate numeric input
    let telegram_id: i64 = match input.parse() {
        Ok(id) if id > 0 => id,
        _ => {
            // Return empty results for invalid input
            bot.answer_inline_query(q.id, Vec::<InlineQueryResult>::new())
                .await?;
            return Ok(());
        }
    };

    // Run the three-tier lookup
    let (title, description, text) = match check_user(telegram_id, &state).await {
        Ok(true) => (
            "✅ ДА",
            format!("ID {} зарегистрирован в Telega", telegram_id),
            format!("✅ ДА — ID {} зарегистрирован в Telega.", telegram_id),
        ),
        Ok(false) => (
            "❌ НЕТ",
            format!("ID {} не найден в Telega", telegram_id),
            format!("❌ НЕТ — ID {} не найден в Telega.", telegram_id),
        ),
        Err(e) => {
            error!("Inline lookup error for ID {}: {}", telegram_id, e);
            (
                "⚠️ Ошибка",
                format!("Не удалось проверить ID {}", telegram_id),
                format!("⚠️ Ошибка при проверке ID {}.", telegram_id),
            )
        }
    };

    let article = InlineQueryResultArticle::new(
        format!("check_{}", telegram_id),
        title,
        InputMessageContent::Text(InputMessageContentText::new(text)),
    )
    .description(description);

    // In teloxide 0.17, use .into() to convert to InlineQueryResult
    bot.answer_inline_query(q.id, vec![article.into()])
        .await?;

    Ok(())
}
