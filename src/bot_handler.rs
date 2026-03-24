use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use moka::future::Cache;
use sqlx::SqlitePool;
use teloxide::prelude::*;
use teloxide::types::{
    ChatKind, InlineQueryResult, InlineQueryResultArticle, InputMessageContent,
    InputMessageContentText,
};
use tracing::{debug, error, info};

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
    /// Deduplication cache for group member tracking.
    /// Maps (chat_id, user_id) → () with a short TTL (~5 min) to avoid
    /// hitting the database on every single message in active chats.
    pub tracking_cache: Cache<(i64, i64), ()>,
}

// ─── Core lookup logic ──────────────────────────────────────────────────────

/// Three-tier lookup: moka cache → SQLite → okcdn.ru API.
///
/// Uses `try_get_with` to prevent cache stampede — concurrent requests for
/// the same `telegram_id` are coalesced: only the first caller executes
/// the closure, the rest wait and receive the cached result.
pub async fn check_user(telegram_id: i64, state: &AppState) -> Result<bool> {
    let pool = state.pool.clone();
    let api = state.api.clone();

    let found = state
        .cache
        .try_get_with(telegram_id, async move {
            // ── Layer 2: SQLite persistent storage ──
            if db::check_telega_id(&pool, telegram_id).await? {
                info!("DB HIT for ID {}", telegram_id);
                return Ok(true);
            }

            // ── Layer 3: Upstream API call ──
            info!("Cache & DB MISS for ID {}. Querying API...", telegram_id);
            let api_result = api.check_id(telegram_id).await?;

            if api_result {
                db::save_telega_id(&pool, telegram_id).await?;
            }

            Ok::<bool, anyhow::Error>(api_result)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Lookup failed: {}", e))?;

    Ok(found)
}

// ─── /start command handler ─────────────────────────────────────────────────

/// Handle the /start command with a greeting message.
pub async fn handle_start(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let greeting = r#"Добро пожаловать в TelegaChecker!

Telega Checker специализированный инструмент для проверки аккаунтов. Основная задача определение, числится ли конкретный Telegram ID в инфраструктуре Telega.

Как пользоваться ботом:
• Просто отправьте мне Telegram ID (только цифры, например: 123456789).
• Используйте inline-режим в любом чате: введите @telega_checker_rs_bot 123456789.
В ответ я мгновенно сообщу, найден ли этот пользователь в системе.

О приватности:
Статья о возможных подводных камнях и уязвимостях при использовании Telega:
<a href="https://telegra.ph/How-Telega-Intercepts-Your-Messages-and-Data-03-24">Как Telega перехватывает ваши сообщения и данные</a>

Связь с разработчиком:
По вопросам сотрудничества, баг-репортам или предложениям обращайтесь: @Berektassuly"#;

    bot.send_message(msg.chat.id, greeting)
        .parse_mode(teloxide::types::ParseMode::Html)
        .await?;

    Ok(())
}

// ─── Text message handler (private chats only) ─────────────────────────────

/// Handle plain text messages in private chats. Expects a numeric Telegram ID.
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
        .cache_time(300) // 5 minutes — explicit control over Telegram-side caching
        .await?;

    Ok(())
}

// ─── Group member tracking handlers ─────────────────────────────────────────

/// Passively track users who send messages in group/supergroup chats.
/// Uses a moka dedup cache to avoid DB writes on every single message.
pub async fn handle_group_message(
    bot: Bot,
    msg: Message,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    // Ignore non-group chats (safety — the dispatcher filter should prevent this)
    let _ = bot;

    let user = match msg.from.as_ref() {
        Some(u) if !u.is_bot => u,
        _ => return Ok(()),
    };

    let chat_id = msg.chat.id.0;
    let user_id = user.id.0 as i64;
    let pair = (chat_id, user_id);

    // Check dedup cache — if recently tracked, skip the DB call
    if state.tracking_cache.get(&pair).await.is_some() {
        return Ok(());
    }

    // Insert into dedup cache (short TTL will auto-expire)
    state.tracking_cache.insert(pair, ()).await;

    // Persist to DB (fire-and-forget)
    if let Err(e) = db::track_chat_member(&state.pool, chat_id, user_id).await {
        error!(chat_id, user_id, "Failed to track chat member: {}", e);
    } else {
        debug!(chat_id, user_id, "Tracked chat member");
    }

    Ok(())
}

/// Handle new members joining a group chat.
pub async fn handle_new_chat_members(
    bot: Bot,
    msg: Message,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    let _ = bot;

    let new_members = match msg.new_chat_members() {
        Some(members) => members,
        None => return Ok(()),
    };

    let chat_id = msg.chat.id.0;

    for user in new_members {
        // Skip bots
        if user.is_bot {
            continue;
        }

        let user_id = user.id.0 as i64;

        // Update dedup cache
        state.tracking_cache.insert((chat_id, user_id), ()).await;

        if let Err(e) = db::track_chat_member(&state.pool, chat_id, user_id).await {
            error!(chat_id, user_id, "Failed to track new chat member: {}", e);
        } else {
            info!(chat_id, user_id, "Tracked new chat member (join)");
        }
    }

    Ok(())
}

/// Handle a member leaving a group chat. Soft-deletes them from db.
pub async fn handle_left_chat_member(
    bot: Bot,
    msg: Message,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    let _ = bot;

    let left_user = match msg.left_chat_member() {
        Some(user) => user,
        None => return Ok(()),
    };

    let chat_id = msg.chat.id.0;
    let user_id = left_user.id.0 as i64;

    // Remove from dedup cache
    state.tracking_cache.remove(&(chat_id, user_id)).await;

    if let Err(e) = db::untrack_chat_member(&state.pool, chat_id, user_id).await {
        error!(chat_id, user_id, "Failed to untrack left chat member: {}", e);
    } else {
        info!(chat_id, user_id, "Untracked chat member (left)");
    }

    Ok(())
}

/// Filter predicate: returns true if the message is from a group or supergroup.
pub fn is_group_chat(msg: &Message) -> bool {
    matches!(msg.chat.kind, ChatKind::Public(_))
}

/// Filter predicate: returns true if the message is from a private chat.
pub fn is_private_chat(msg: &Message) -> bool {
    matches!(msg.chat.kind, ChatKind::Private(_))
}
