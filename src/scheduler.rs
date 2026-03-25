use std::sync::Arc;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use teloxide::prelude::*;
use teloxide::types::ChatId;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, warn};

use crate::bot_handler::{check_user, AppState};
use crate::db;

/// Maximum number of concurrent API checks during the daily scan.
/// Prevents overloading the external calls.okcdn.ru API.
const MAX_CONCURRENT_CHECKS: usize = 10;

/// Start the daily scan scheduler. Spawns a background task that runs
/// the Telega scan at 09:00 UTC every day.
///
/// Returns the `JobScheduler` handle so the caller can shut it down
/// gracefully when the application exits.
pub async fn start_daily_scan(bot: Bot, state: AppState) -> Result<JobScheduler> {
    let sched = JobScheduler::new()
        .await
        .context("Failed to create job scheduler")?;

    // Wrap in Arc so the closure can capture them
    let bot = Arc::new(bot);
    let state = Arc::new(state);

    let job = Job::new_async("0 0 9 * * *", move |_uuid, _lock| {
        let bot = bot.clone();
        let state = state.clone();
        Box::pin(async move {
            info!("Starting daily Telega scan...");
            if let Err(e) = run_scan(&bot, &state).await {
                error!("Daily scan failed: {}", e);
            }
        })
    })
    .context("Failed to create daily scan job")?;

    sched
        .add(job)
        .await
        .context("Failed to add daily scan job to scheduler")?;

    sched
        .start()
        .await
        .context("Failed to start job scheduler")?;

    info!("Daily scan scheduler started (09:00 UTC)");
    Ok(sched)
}

/// Execute the full scan: iterate over all active chats, check each
/// member through the 3-tier lookup, and send reports for chats with hits.
async fn run_scan(bot: &Bot, state: &AppState) -> Result<()> {
    let chat_ids = db::get_active_chat_ids(&state.pool).await?;
    info!(count = chat_ids.len(), "Scanning active chats");

    for chat_id in chat_ids {
        if let Err(e) = scan_chat(bot, state, chat_id).await {
            error!(chat_id, "Error scanning chat: {}", e);
            // Don't break — continue to the next chat
        }
    }

    info!("Daily scan completed");
    Ok(())
}

/// Scan a single chat: check all its active members and send
/// a report if any Telega users are found.
async fn scan_chat(bot: &Bot, state: &AppState, chat_id: i64) -> Result<()> {
    let members = db::get_active_members(&state.pool, chat_id).await?;
    if members.is_empty() {
        return Ok(());
    }

    info!(chat_id, member_count = members.len(), "Scanning chat members");

    // Check all members with bounded concurrency
    let hits: Vec<i64> = stream::iter(members)
        .map(|user_id| {
            let state = state.clone();
            async move {
                match check_user(user_id, &state).await {
                    Ok(true) => Some(user_id),
                    Ok(false) => None,
                    Err(e) => {
                        error!(user_id, "Lookup error during scan: {}", e);
                        None
                    }
                }
            }
        })
        .buffer_unordered(MAX_CONCURRENT_CHECKS)
        .filter_map(|opt| async move { opt })
        .collect()
        .await;

    // Only send a report if there are positive hits
    if hits.is_empty() {
        return Ok(());
    }

    // Format the report message
    let user_list: String = hits
        .iter()
        .enumerate()
        .map(|(i, id)| format!("{}. <a href=\"tg://user?id={}\">{}</a>", i + 1, id, id))
        .collect::<Vec<_>>()
        .join("\n");

    let report = format!(
        "🛡 <b>Daily Scan Report</b>\n\n\
         The following members are using the compromised Telega client:\n\n\
         {}",
        user_list
    );

    info!(chat_id, hits = hits.len(), "Sending scan report");

    match bot
        .send_message(ChatId(chat_id), &report)
        .parse_mode(teloxide::types::ParseMode::Html)
        .await
    {
        Ok(_) => {
            info!(chat_id, "Scan report sent successfully");
        }
        Err(teloxide::RequestError::Api(ref api_err))
            if matches!(
                api_err,
                teloxide::ApiError::BotKicked
                    | teloxide::ApiError::BotKickedFromSupergroup
                    | teloxide::ApiError::ChatNotFound
                    | teloxide::ApiError::UserDeactivated
                    | teloxide::ApiError::GroupDeactivated
            ) =>
        {
            warn!(
                chat_id,
                "Bot was removed or lacks permissions in chat: {}. Deactivating.", api_err
            );
            if let Err(e) = db::deactivate_chat(&state.pool, chat_id).await {
                error!(chat_id, "Failed to deactivate chat after kick: {}", e);
            }
        }
        Err(e) => {
            error!(chat_id, "Failed to send scan report: {}", e);
        }
    }

    Ok(())
}
