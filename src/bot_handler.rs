use std::sync::Arc;

use anyhow::Result;
use moka::future::Cache;
use sqlx::SqlitePool;
use teloxide::prelude::*;
use teloxide::types::{
    ChatKind, InlineKeyboardButton, InlineKeyboardMarkup, InlineQueryResult,
    InlineQueryResultArticle, InputFile, InputMessageContent, InputMessageContentText, Me,
};
use tracing::{debug, error, info, warn};

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
    /// Telegram user ID of the bot administrator.
    pub admin_id: i64,
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

/// Handle the /start command with a greeting message and plugin download button.
pub async fn handle_start(bot: Bot, msg: Message) -> Result<(), teloxide::RequestError> {
    let greeting = r#"Добро пожаловать в TelegaChecker!

Telega Checker специализированный инструмент для проверки аккаунтов. Основная задача определение, числится ли конкретный Telegram ID в инфраструктуре Telega.

Как пользоваться ботом:
• Просто отправьте мне Telegram ID (только цифры, например: 123456789).
• Используйте inline-режим в любом чате: введите @telega_checker_rs_bot 123456789.
• В группе просто упомяните меня: @telega_checker_rs_bot 123456789.
В ответ я мгновенно сообщу, найден ли этот пользователь в системе.

О приватности:
Статья о возможных подводных камнях и уязвимостях при использовании Telega:
<a href="https://telegra.ph/How-Telega-Intercepts-Your-Messages-and-Data-03-24">Как Telega перехватывает ваши сообщения и данные</a>

Связь с разработчиком:
По вопросам сотрудничества, баг-репортам или предложениям обращайтесь: @Berektassuly"#;

    let keyboard = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback(
        "Скачать плагины и получить API ключ",
        "get_plugins",
    )]]);

    bot.send_message(msg.chat.id, greeting)
        .parse_mode(teloxide::types::ParseMode::Html)
        .reply_markup(keyboard)
        .await?;

    Ok(())
}

// ─── /plugins command handler (private chats only) ─────────────────────────

/// Handle the /plugins command: deliver plugin assets + API token.
pub async fn handle_plugins(
    bot: Bot,
    msg: Message,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    // Only work in private chats
    if !is_private_chat(&msg) {
        bot.send_message(msg.chat.id, "Эта команда доступна только в личных сообщениях.")
            .await?;
        return Ok(());
    }

    let user_id = msg.from.as_ref().map(|u| u.id.0 as i64).unwrap_or(0);
    if user_id == 0 {
        return Ok(());
    }

    send_plugins_and_token(&bot, msg.chat.id, user_id, &state).await
}

// ─── /upload_assets command handler (admin only) ────────────────────────────

/// Handle the /upload_assets command: upload plugin files to Telegram and
/// store their file_ids in the database. Admin-only.
pub async fn handle_upload_assets(
    bot: Bot,
    msg: Message,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    let user_id = msg.from.as_ref().map(|u| u.id.0 as i64).unwrap_or(0);

    // Admin guard (defense-in-depth — dispatcher also filters)
    if user_id != state.admin_id {
        warn!(user_id, "Unauthorized /upload_assets attempt");
        return Ok(());
    }

    bot.send_message(msg.chat.id, "Загрузка плагинов из директории plugins/...")
        .await?;

    // Read .plugin files from the plugins/ directory
    let plugin_dir = std::path::Path::new("plugins");
    if !plugin_dir.exists() || !plugin_dir.is_dir() {
        bot.send_message(
            msg.chat.id,
            "Директория plugins/ не найдена. Убедитесь, что бот запущен из корня проекта.",
        )
        .await?;
        return Ok(());
    }

    let mut uploaded_count = 0u32;
    let mut errors = Vec::new();

    let entries = match std::fs::read_dir(plugin_dir) {
        Ok(e) => e,
        Err(e) => {
            bot.send_message(msg.chat.id, format!("Ошибка чтения директории: {}", e))
                .await?;
            return Ok(());
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) if name.ends_with(".plugin") => name.to_string(),
            _ => continue,
        };

        // Derive the friendly asset name from the filename
        // e.g. "telega_checker_rust_AyuGram.plugin" → "ayugram"
        let asset_name = derive_asset_name(&file_name);

        info!(file = %file_name, asset_name = %asset_name, "Uploading plugin asset");

        // Upload the file to Telegram (sends it to the admin chat)
        match bot
            .send_document(msg.chat.id, InputFile::file(&path))
            .await
        {
            Ok(sent_msg) => {
                // Extract the file_id from the sent document
                if let Some(doc) = sent_msg.document() {
                    let file_id = &doc.file.id.0;
                    if let Err(e) =
                        db::upsert_plugin_asset(&state.pool, &asset_name, file_id).await
                    {
                        error!(asset_name, "Failed to upsert plugin asset: {}", e);
                        errors.push(format!("{}: DB error", asset_name));
                    } else {
                        info!(asset_name, file_id, "Plugin asset uploaded and stored");
                        uploaded_count += 1;
                    }
                } else {
                    errors.push(format!("{}: no document in response", asset_name));
                }
            }
            Err(e) => {
                error!(file = %file_name, "Failed to upload plugin: {}", e);
                errors.push(format!("{}: upload failed", asset_name));
            }
        }
    }

    // Send summary
    let mut summary = format!("Загружено плагинов: {}", uploaded_count);
    if !errors.is_empty() {
        summary.push_str(&format!("\nОшибки:\n{}", errors.join("\n")));
    }

    bot.send_message(msg.chat.id, summary).await?;
    Ok(())
}

// ─── /delete_asset command handler (admin only) ─────────────────────────────

/// Handle the /delete_asset command: remove a plugin asset from the database.
pub async fn handle_delete_asset(
    bot: Bot,
    msg: Message,
    state: AppState,
    asset_name: String,
) -> Result<(), teloxide::RequestError> {
    let user_id = msg.from.as_ref().map(|u| u.id.0 as i64).unwrap_or(0);

    // Admin guard
    if user_id != state.admin_id {
        warn!(user_id, "Unauthorized /delete_asset attempt");
        return Ok(());
    }

    let asset_name = asset_name.trim();

    if asset_name.is_empty() {
        bot.send_message(
            msg.chat.id,
            "Пожалуйста, укажите имя плагина. Пример: <code>/delete_asset ayugram</code>",
        )
        .parse_mode(teloxide::types::ParseMode::Html)
        .await?;
        return Ok(());
    }

    match db::delete_plugin_asset(&state.pool, asset_name).await {
        Ok(true) => {
            info!(asset_name, "Plugin asset deleted successfully");
            bot.send_message(
                msg.chat.id,
                format!("Плагин <b>{}</b> успешно удалён.", asset_name),
            )
            .parse_mode(teloxide::types::ParseMode::Html)
            .await?;
        }
        Ok(false) => {
            bot.send_message(
                msg.chat.id,
                format!("Плагин <b>{}</b> не найден.", asset_name),
            )
            .parse_mode(teloxide::types::ParseMode::Html)
            .await?;
        }
        Err(e) => {
            error!(asset_name, "Failed to delete plugin asset: {}", e);
            bot.send_message(msg.chat.id, "Произошла ошибка при удалении плагина.")
                .await?;
        }
    }

    Ok(())
}

// ─── Callback query handler ────────────────────────────────────────────────

/// Handle inline button callbacks: "get_plugins" and "reset_token".
pub async fn handle_callback_query(
    bot: Bot,
    q: CallbackQuery,
    state: AppState,
) -> Result<(), teloxide::RequestError> {
    let data = match q.data.as_deref() {
        Some(d) => d,
        None => return Ok(()),
    };

    let user_id = q.from.id.0 as i64;

    match data {
        "get_plugins" => {
            // Answer the callback to remove the loading spinner
            bot.answer_callback_query(q.id.clone()).await?;

            // Use the chat from the original message
            if let Some(msg) = q.message {
                let chat_id = msg.chat().id;
                if let Err(e) = send_plugins_and_token(&bot, chat_id, user_id, &state).await {
                    error!(user_id, "Failed to handle get_plugins callback: {}", e);
                }
            }
        }
        "reset_token" => {
            // Rotate the token
            match db::rotate_token(&state.pool, user_id).await {
                Ok(new_token) => {
                    bot.answer_callback_query(q.id.clone())
                        .text("Токен обновлён!")
                        .await?;

                    if let Some(msg) = q.message {
                        let chat_id = msg.chat().id;
                        let text = format!(
                            "<b>Ваш новый API токен:</b>\n\n\
                             <code>{}</code>\n\n\
                             Обновите токен в настройках плагина.",
                            new_token
                        );
                        let keyboard =
                            InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback(
                                "Сбросить API токен",
                                "reset_token",
                            )]]);

                        bot.send_message(chat_id, text)
                            .parse_mode(teloxide::types::ParseMode::Html)
                            .reply_markup(keyboard)
                            .await?;
                    }
                }
                Err(e) => {
                    error!(user_id, "Failed to rotate token: {}", e);
                    bot.answer_callback_query(q.id.clone())
                        .text("Ошибка при обновлении токена")
                        .await?;
                }
            }
        }
        _ => {
            debug!(data, "Unknown callback query data");
            bot.answer_callback_query(q.id.clone()).await?;
        }
    }

    Ok(())
}

// ─── Shared plugin delivery logic ───────────────────────────────────────────

/// Core logic for delivering plugins and API token. Shared between
/// the /plugins command and the "get_plugins" callback button.
async fn send_plugins_and_token(
    bot: &Bot,
    chat_id: ChatId,
    user_id: i64,
    state: &AppState,
) -> Result<(), teloxide::RequestError> {
    // Get or create the user's API token
    let token = match db::get_or_create_token(&state.pool, user_id).await {
        Ok(t) => t,
        Err(e) => {
            error!(user_id, "Failed to get/create token: {}", e);
            bot.send_message(chat_id, "Ошибка при создании API токена.")
                .await?;
            return Ok(());
        }
    };

    // Fetch stored plugin assets
    let assets = match db::get_plugin_assets(&state.pool).await {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to fetch plugin assets: {}", e);
            bot.send_message(chat_id, "Ошибка при загрузке плагинов.")
                .await?;
            return Ok(());
        }
    };

    if assets.is_empty() {
        bot.send_message(
            chat_id,
            "Плагины ещё не загружены. Администратор должен выполнить /upload_assets.",
        )
        .await?;
        return Ok(());
    }

    // Send each plugin asset as a document using cached file_id (zero bandwidth)
    for (name, file_id) in &assets {
        if let Err(e) = bot
            .send_document(chat_id, InputFile::file_id(teloxide::types::FileId(file_id.clone())))
            .await
        {
            error!(name, "Failed to send plugin asset: {}", e);
        }
    }

    // Build the instruction message
    let instruction = format!(
        r#"<b>Инструкция по установке плагинов</b>

1. Скачайте файл(ы) плагина выше.
2. Переместите .plugin файл в папку <code>plugins/</code> вашего Telegram-клиента (AyuGram или exteraGram).
3. В настройках плагина укажите ваш персональный API-токен:

<b>Ваш API токен:</b>
<code>{token}</code>

4. Укажите базовый URL (API URL):
<code>https://tc.berektassuly.com</code>

<b>Важно:</b>
• Токен привязан к вашему Telegram аккаунту.
• Не передавайте токен третьим лицам.
• При компрометации — нажмите кнопку ниже для сброса.

Подробная инструкция: /plugins"#
    );

    let keyboard = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton::callback(
        "Сбросить API токен",
        "reset_token",
    )]]);

    bot.send_message(chat_id, instruction)
        .parse_mode(teloxide::types::ParseMode::Html)
        .reply_markup(keyboard)
        .await?;

    info!(user_id, "Plugins and token delivered");
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
                "Пожалуйста, отправь корректный Telegram ID (только цифры).",
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

// ─── Group mention lookup handler ───────────────────────────────────────────

/// Handle `@bot_username <telegram_id>` mentions in group/supergroup chats.
/// Uses the auto-injected `Me` to dynamically resolve the bot's username.
pub async fn handle_mention_lookup(
    bot: Bot,
    msg: Message,
    state: AppState,
    me: Me,
) -> Result<(), teloxide::RequestError> {
    // Resolve the bot's username at runtime
    let bot_username = me.username();

    let text = match msg.text() {
        Some(t) => t.trim(),
        None => return Ok(()),
    };

    // Check if the message starts with @bot_username (case-insensitive)
    let mention = format!("@{}", bot_username);
    if !text.to_lowercase().starts_with(&mention.to_lowercase()) {
        return Ok(());
    }

    // Extract everything after the mention and try to parse as a Telegram ID
    let remainder = text[mention.len()..].trim();
    let telegram_id: i64 = match remainder.parse() {
        Ok(id) if id > 0 => id,
        _ => return Ok(()), // Silently ignore invalid input in groups
    };

    // Log the bot user (fire-and-forget)
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
            error!("Mention lookup error for ID {}: {}", telegram_id, e);
            ("⚠️ Ошибка при проверке.", "ERROR")
        }
    };

    // Log the request
    if let Err(e) = db::log_request(&state.pool, user_id, telegram_id, result_short).await {
        error!("Failed to log request: {}", e);
    }

    bot.send_message(msg.chat.id, reply_text).await?;

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

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Derive a friendly asset name from a plugin filename.
/// e.g. "telega_checker_rust_AyuGram.plugin" → "ayugram"
/// e.g. "telega_checker_rust_exteraGram.plugin" → "extragam"
fn derive_asset_name(filename: &str) -> String {
    // Strip extension
    let stem = filename.strip_suffix(".plugin").unwrap_or(filename);
    // Take the last segment after underscore (the client name)
    let name = stem.rsplit('_').next().unwrap_or(stem);
    // Normalize: lowercase, remove non-alphanumeric
    name.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}
