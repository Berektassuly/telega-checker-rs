# TelegaChecker — Docker Deployment Guide

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) installed
- A valid Telegram bot token from [@BotFather](https://t.me/BotFather)

## 1. Configure Environment

Copy the example and fill in your secrets:

```bash
cp .env.example .env
# Edit .env and set TELOXIDE_TOKEN to your real bot token
```

> **Note:** `DATABASE_URL` is overridden by `docker-compose.yml` to point to the persistent volume (`/app/data/telega_checker.db`). You do NOT need to change it in `.env` for Docker deployments.

## 2. Build & Start

```bash
# Build the image and start the bot in detached mode
docker compose up -d --build
```

First build will take several minutes (Rust compilation). Subsequent builds are much faster thanks to Docker layer caching.

## 3. View Logs

```bash
# Follow live logs
docker compose logs -f

# View last 100 lines
docker compose logs --tail 100
```

## 4. Stop the Bot

```bash
# Stop (keeps volume data)
docker compose down

# Stop and delete the SQLite volume (⚠️ destroys all data)
docker compose down -v
```

## 5. Update & Redeploy

```bash
# Pull latest code changes, rebuild, and restart
docker compose up -d --build
```

The named volume `bot_data` persists across container recreations — your SQLite database survives `down` + `up` cycles.

## Volume Info

| Volume | Container Path | Purpose |
|--------|---------------|---------|
| `bot_data` | `/app/data` | SQLite database (`telega_checker.db`) |

To inspect the volume:

```bash
docker volume inspect telega-checker-rs_bot_data
```
