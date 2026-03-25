# telega-checker-rs

*Прочитать на других языках: [English](../README.md), [Русский](README_RU.md).*

Высокопроизводительный Telegram-бот и HTTP API для обнаружения аккаунтов, скомпрометированных MITM-форком **Telega**. Написан на Rust. Реализует архитектуру **Dual-Core BFF (Backend-For-Frontend)**: Telegram-бот (teloxide long-polling) и HTTP API-сервер (axum) работают параллельно на одном tokio-рантайме, совместно используя один и тот же `AppState` (moka-кеш, SQLite-пул, API-клиент). Работает в трёх режимах: **реактивный** (личные сообщения / inline-запросы), **пассивный** (мониторинг групп с ежедневным сканированием) и **HTTP API** (RESTful-эндпоинт для внешних клиентов, таких как Android-плагин). Возвращает бинарный результат: присутствует или отсутствует в VoIP-инфраструктуре Telega.

Это production-версия на Rust, портированная с [notelega](https://github.com/hlnmplus/notelega) (Python/aiogram PoC). Python-реализация валидирует концепцию детектирования; данная реализация спроектирована для устойчивой конкурентной нагрузки, субмикросекундного чтения из кеша, встроенной защиты от cache stampede и потребления памяти на два порядка меньше, чем у CPython-эквивалента.

## Содержание

- [Контекст угрозы](#контекст-угрозы)
- [Индикаторы компрометации](#индикаторы-компрометации)
- [Механизм детектирования](#механизм-детектирования)
- [Архитектура](#архитектура)
- [Диаграмма архитектуры угрозы](#диаграмма-архитектуры-угрозы)
- [Диаграмма процесса детектирования](#диаграмма-процесса-детектирования)
- [Сравнительная матрица: официальный Telegram vs. Telega](#сравнительная-матрица-официальный-telegram-vs-telega)
- [Метрики производительности: Python PoC vs. Rust](#метрики-производительности-python-poc-vs-rust)
- [Структура проекта](#структура-проекта)
- [Требования](#требования)
- [Конфигурация](#конфигурация)
- [Развёртывание](#развёртывание)
- [Использование](#использование)
- [HTTP API](#http-api)
- [Пассивный мониторинг групп](#пассивный-мониторинг-групп)
- [Схема базы данных](#схема-базы-данных)
- [Приватность и псевдонимизация аналитики](#приватность-и-псевдонимизация-аналитики)
- [Заметки по операционной безопасности](#заметки-по-операционной-безопасности)
- [Клиентские плагины](#клиентские-плагины)
- [Лицензия](#лицензия)

---

## Контекст угрозы

**Telega** (ранее "Dal") -- Android-форк Telegram, позиционируемый как альтернатива, обходящая ограничения Роскомнадзора на голосовые/видеозвонки и доставку медиа. За этой функциональностью скрывается полноценная MITM-прокси-инфраструктура. Независимый реверс-инжиниринг (декомпиляция APK через jadx/IDA Pro, сетевой анализ и экспериментальная верификация MTProto-хендшейков) подтвердил следующую цепочку атаки:

1. **Подмена адресов DC.** При запуске Telega получает подменные IP-адреса дата-центров с `api.telega.info/v1/dc-proxy`. Все возвращаемые адреса находятся в диапазоне `130.49.152.0/24` (AS203502, АО "ТЕЛЕГА"). Метод `native_setDcVersion()` передаёт их в C++-движок Telegram, в результате чего клиент подключается к серверам Telega вместо DC1-DC5 Telegram.

2. **Инъекция RSA-ключа.** Нативная библиотека `libtmessages.49.so` содержит четыре публичных RSA-ключа. Официальный клиент Telegram содержит три. Четвёртый ключ (отпечаток `0x2c945714333b5ebd`) отклоняется серверами Telegram (`transport error -404`), но принимается прокси-серверами Telega (`server_DH_params_ok`). Владение соответствующим закрытым ключом обеспечивает классическую MITM-атаку: одна зашифрованная сессия с клиентом, отдельная сессия с реальным сервером Telegram.

3. **Отключение PFS.** Конфигурация, возвращаемая `/v1/dc-proxy`, устанавливает `usePfs: false`, отключая Perfect Forward Secrecy. Без PFS оператор, записывающий зашифрованный трафик, может дешифровать его ретроактивно при получении ключа авторизации.

4. **Блокировка секретных чатов.** Firebase Remote Config (`templateVersion: 472`) устанавливает `enable_sc: false`. Кнопка в UI скрыта, входящие запросы секретных чатов молча отклоняются `SecretChatHelper.acceptSecretChat()`, deep-ссылки не обрабатываются. Ни одна из сторон не получает уведомления.

5. **Принудительная переаутентификация.** Четыре удалённых триггера принуждают к сбросу сессии и повторному входу через прокси: push-уведомления (`dc_update_version`, `dc_force_switch`), deep-ссылка (`tg://dc_event?force_relogin=true`) и промо-баннер через `DCMigrationHelper`.

6. **Маршрутизация звонков через OK.ru.** Звонки маршрутизируются через `calls.okcdn.ru` / `api.ok.ru` (инфраструктура VK/Одноклассники) вместо серверов Telegram. VoIP-модуль (`QuicClientConnectionImpl.java:1009`) полностью отключает проверку SSL-сертификатов для QUIC/HTTP3 сигнализации звонков.

Единственный upstream-провайдер AS203502 -- **AS47764 (ООО "ВК")**. Анализ панели модерации Telega (`demo.stage.telega.info`) выявил запросы Роскомнадзора на ограничение каналов (`stream@rkn.gov.ru`) и сервис AI-модерации сообщений в реальном времени (Cerberus).

---

## Индикаторы компрометации

| Индикатор | Значение |
|---|---|
| **AS прокси** | AS203502 (АО "ТЕЛЕГА") |
| **Upstream AS** | AS47764 (ООО "ВК") |
| **Диапазон IP DC** | `130.49.152.0/24` |
| **Отпечаток подменного RSA-ключа** | `0x2c945714333b5ebd` |
| **Статус PFS** | Отключён (`usePfs: false`) |
| **Флаг секретных чатов** | `enable_sc: false` (Firebase Remote Config) |
| **Эндпоинт конфигурации DC** | `api.telega.info/v1/dc-proxy` |
| **Сигнализация звонков** | `calls.okcdn.ru`, `api.ok.ru` |
| **Нативная библиотека** | `libtmessages.49.so` (4 RSA-ключа по смещению `0x15788E1`) |

---

## Механизм детектирования

Форк Telega маршрутизирует голосовые и видеозвонки через VoIP-бэкенд VK/Одноклассники на `calls.okcdn.ru`. Этот бэкенд предоставляет недокументированный API-эндпоинт, который связывает внешние (Telegram) user ID с внутренними идентификаторами OK.ru. Если для заданного Telegram ID существует такая связь, данный аккаунт взаимодействовал с инфраструктурой звонков Telega и, следовательно, скомпрометирован.

### Протокол API

**Аутентификация:**

```
POST https://calls.okcdn.ru/api/auth/anonymLogin
Content-Type: application/x-www-form-urlencoded

application_key=<APPLICATION_KEY>&session_data={"device_id":"telega_checker_bot","version":2,"client_version":"android_8","client_type":"SDK_ANDROID"}
```

Возвращает: `{"session_key": "<token>"}`

**Запрос проверки:**

```
POST https://calls.okcdn.ru/api/vchat/getOkIdsByExternalIds
Content-Type: application/x-www-form-urlencoded

application_key=<APPLICATION_KEY>&session_key=<SESSION_KEY>&externalIds=[{"id":"<TELEGRAM_ID>","ok_anonym":false}]
```

При совпадении: `{"ids": [{"ok_user_id": <int>, "external_user_id": {"id": "<TELEGRAM_ID>", "ok_anonym": false}}]}`
При отсутствии: `{"error_code": 4, ...}` или `{"ids": []}`

Сессионный ключ периодически истекает. Реализация обрабатывает это прозрачно через повторный запрос при 401/403 с double-checked locking для предотвращения избыточной переаутентификации при конкурентном доступе. Rate-лимиты API (HTTP 429) обрабатываются через экспоненциальный backoff (до 4 повторов: 1с → 2с → 4с → 8с).

---

## Архитектура

Приложение реализует дизайн **Dual-Core**: Telegram-бот (teloxide) и HTTP API-сервер (axum) работают параллельно на одном tokio-рантайме через `tokio::select!`, совместно используя единый `AppState`. Это гарантирует, что попадание в кеш со стороны бота мгновенно приносит пользу API, и наоборот. Оба ядра используют трёхуровневый поиск с различными характеристиками задержки и персистентности на каждом уровне. Бот дополнительно работает как пассивный монитор групп с ежедневным плановым сканированием. Выделенная ветка `tokio::signal::ctrl_c()` обеспечивает graceful shutdown всех подсистем — HTTP-сервера, Telegram-диспетчера и планировщика ежедневного сканирования — при SIGTERM или Ctrl+C.

### Сетевая топология

```
Android-плагин ──HTTPS──▶ Cloudflare Edge (SSL-терминация)
                                    │
                              Cloudflare Tunnel
                            (исходящее соединение,
                             входящие порты не нужны)
                                    │
                                    ▼
Telegram ──Long Polling──▶ Rust-контейнер :8080
                              ┌─────────────────┐
                              │   tokio runtime │
                              │  ┌─────┐ ┌─────┐│
                              │  │Axum │ │Telox││
                              │  │ API │ │ ide ││
                              │  └──┬──┘ └──┬──┘│
                              │     └───┬───┘   │
                              │    AppState     │
                              │  (общий, zero-  │
                              │   cost clones)  │
                              └─────────────────┘
```

Rust-контейнер подключается к публичному интернету через **Cloudflare Tunnel** (`cloudflared`). Туннель устанавливает исходящее соединение с edge-сетью Cloudflare — входящие порты на хост-машине не требуются, что исключает необходимость проброса портов, настройки reverse proxy или origin SSL-сертификатов. Cloudflare обрабатывает SSL-терминацию, DDoS-защиту и rate limiting на edge. Контейнер **не** выставляет порты на хост — только во внутреннюю Docker-сеть, где его достигает `cloudflared`.

### Конвейер пассивного мониторинга

При добавлении в группу бот бесшумно отслеживает участников через три источника событий:

1. **Наблюдение за сообщениями** — каждое сообщение в группе записывает `(chat_id, user_id)` в таблицу `chat_members`. Moka-кеш дедупликации (TTL 5 мин, ёмкость 50K) предотвращает I/O базы данных при каждом сообщении.
2. **События вступления** — обновления `NewChatMembers` отслеживаются немедленно (минуя дедупликацию).
3. **События выхода** — `LeftChatMember` выполняет мягкое удаление (`is_active = FALSE`).

### Ежедневное сканирование

Задача `tokio-cron-scheduler` запускается ежедневно в **09:00 UTC**. Хэндл планировщика хранится в `main.rs` и корректно завершается при выходе из приложения (без утечек ресурсов):

1. Получает все уникальные `chat_id` с активными участниками из `chat_members`.
2. Для каждого чата проверяет все активные `user_id` через трёхуровневый поиск.
3. Ограничивает конкурентные API-проверки до 10 через `futures::stream::buffer_unordered`.
4. Rate-лимиты API (HTTP 429) поглощаются прозрачно через экспоненциальный backoff — отдельные запросы повторяются до 4 раз (1с → 2с → 4с → 8с) без блокировки tokio-рантайма.
5. Отправляет агрегированный HTML-отчёт в чаты с положительными результатами. Тишина, если находок нет.
6. **Самоочистка**: если отправка не удаётся с ошибками `BotKicked` / `ChatNotFound` и подобными, все участники этого чата мягко удаляются для экономии ресурсов при будущих сканированиях.

### Трёхуровневый поиск

```
Telegram Update (Message | InlineQuery | HTTP API)
        |
        v
   Валидация ввода (parse i64, отклонение неположительных)
        |
        v
+-------+---------------------------+
| L1: Moka In-Memory Cache          |
| - Cache<i64, bool>                |
| - Ёмкость 100 000 записей (LRU)  |
| - TTL 24 часа (positive+negative) |
| - try_get_with: stampede-safe      |
+-------+---------------------------+
        | MISS
        v
+-------+---------------------------+
| L2: SQLite (WAL mode)             |
| - Таблица known_users             |
| - Поиск по INTEGER PRIMARY KEY    |
| - Только положительные результаты |
+-------+---------------------------+
        | MISS
        v
+-------+---------------------------+
| L3: API calls.okcdn.ru            |
| - POST getOkIdsByExternalIds      |
| - Управление сессией через RwLock |
| - Double-checked refresh при 401  |
| - Положит. результаты → L2        |
+-------+---------------------------+
        |
        v
   Ответ (Telegram / HTTP JSON)
```

### Защита от cache stampede

`moka::future::Cache::try_get_with` -- ключевой примитив конкурентности. Когда N одновременных запросов приходят для одного некешированного `telegram_id`, ровно один вызывающий входит в асинхронное замыкание (путь L2 + L3). Остальные N-1 вызывающих блокируются на внутреннем waiter и получают результат по завершении работы первого вызывающего. Это исключает избыточные запросы к базе данных и API при пиковой нагрузке.

### Управление сессией

`ApiClient` хранит сессионный ключ за `tokio::sync::RwLock<Option<String>>`. Множество обработчиков читают конкурентно (`RwLock::read`); при 401/403 `refresh_session` захватывает write-блокировку и выполняет double-checked locking: если другая задача уже обновила ключ, пока текущая ждала блокировку, обновление пропускается. Это предотвращает ситуацию, когда N конкурентных ошибок вызывают N запросов аутентификации.

### Обработка rate-лимитов API

Ответы HTTP 429 от `calls.okcdn.ru` обрабатываются через **экспоненциальный backoff**. Когда API возвращает 429 (Too Many Requests), клиент повторяет запрос до 4 раз с возрастающими задержками: 1с → 2с → 4с → 8с. Backoff использует `tokio::time::sleep` (неблокирующий — не останавливает tokio-рантайм). Если все повторы исчерпаны, ошибка передаётся вызывающему. Это критически важно для ежедневного сканирования, где сотни конкурентных запросов могут вызвать rate limiting.

---

## Диаграмма архитектуры угрозы

Следующая диаграмма иллюстрирует расхождение между легитимной MTProto-сессией Telegram и сессией, маршрутизированной через MITM-инфраструктуру Telega (AS203502 / AS47764).

```mermaid
flowchart TB
    subgraph CLIENT["Устройство клиента"]
        OC["Официальный клиент Telegram"]
        TC["Форк-клиент Telega<br/><i>libtmessages.49.so</i>"]
    end

    subgraph OFFICIAL["Официальный путь Telegram"]
        direction TB
        TG_DC["Telegram DC1-DC5<br/>149.154.167.x<br/><b>3 RSA-ключа (hardcoded)</b>"]
    end

    subgraph TELEGA_INFRA["MITM-инфраструктура Telega"]
        direction TB
        DC_PROXY["api.telega.info/v1/dc-proxy<br/><i>Возвращает подменные IP DC</i><br/><i>usePfs: false</i>"]
        TELEGA_PROXY["Прокси-серверы Telega<br/>130.49.152.0/24<br/>AS203502 (АО ТЕЛЕГА)<br/><b>4-й RSA-ключ: 0x2c945714333b5ebd</b>"]
        FIREBASE["Firebase Remote Config<br/><i>templateVersion: 472</i><br/><i>enable_sc: false</i>"]
        RELOGIN["Триггеры принудительного<br/>повторного входа<br/>push: dc_update_version<br/>push: dc_force_switch<br/>deeplink: tg://dc_event<br/>banner: DCMigrationHelper"]
    end

    subgraph UPSTREAM["Upstream-провайдер"]
        VK["AS47764 (ООО ВК)<br/><i>Единственный upstream AS203502</i>"]
    end

    subgraph CALL_INFRA["Перехват звонков"]
        OKCDN["calls.okcdn.ru<br/>api.ok.ru<br/><i>SSL-верификация отключена</i><br/><i>QUIC/HTTP3 сигнализация</i>"]
    end

    OC -- "MTProto 2.0<br/>PFS включён<br/>Секретные чаты доступны" --> TG_DC

    TC -- "HTTP GET (при запуске)" --> DC_PROXY
    DC_PROXY -- "Подменные IP DC<br/>130.49.152.x" --> TC
    TC -- "MTProto-хендшейк<br/>4-й RSA-ключ принят<br/>PFS отключён" --> TELEGA_PROXY
    TELEGA_PROXY -- "Отдельная MTProto-сессия<br/>(оператор владеет обоими ключами)" --> TG_DC
    TELEGA_PROXY --- VK
    FIREBASE -- "Ежечасное получение конфига<br/>Секретные чаты заблокированы" --> TC
    RELOGIN -- "Сброс сессии +<br/>переаутентификация через прокси" --> TC
    TC -- "VoIP (без cert pinning)" --> OKCDN

    style TELEGA_INFRA fill:#3d0000,stroke:#ff4444,stroke-width:2px,color:#ffffff
    style OFFICIAL fill:#002200,stroke:#44ff44,stroke-width:2px,color:#ffffff
    style CLIENT fill:#1a1a2e,stroke:#888,color:#ffffff
    style UPSTREAM fill:#2a1a00,stroke:#ff8800,stroke-width:1px,color:#ffffff
    style CALL_INFRA fill:#3d0000,stroke:#ff4444,stroke-width:1px,color:#ffffff
```

**Возможности оператора при активации MITM:** чтение всех облачных чатов; просмотр полной истории сообщений и метаданных (IP, устройство, ОС); модификация трафика в реальном времени; выполнение любых действий от имени пользователя (подписка, отправка, удаление); хранение и передача расшифрованных данных третьим сторонам, включая государственные структуры. Секретные чаты молча подавляются; собеседник не получает уведомления об отклонении.

---

## Диаграмма процесса детектирования

Бот реализует трёхуровневый поиск с защитой от cache stampede через `moka::future::Cache::try_get_with`. Конкурентные запросы для одного Telegram ID объединяются на уровне L1; только первый вызывающий выполняет замыкание.

```mermaid
flowchart TD
    INPUT["Telegram Update<br/>(Message | InlineQuery)"] --> VALIDATE{"Парсинг i64<br/>telegram_id > 0?"}
    VALIDATE -- "Невалидный" --> REJECT["Возврат ошибки /<br/>пустой inline-результат"]
    VALIDATE -- "Валидный" --> L1

    subgraph CACHE_LAYER["L1: Moka In-Memory Cache"]
        L1["cache.try_get_with(id, ...)"]
        L1 --> L1_CHECK{"Попадание<br/>в кеш?"}
        L1_CHECK -- "HIT (true|false)" --> L1_RETURN["Возврат кешированного bool"]
    end

    L1_CHECK -- "MISS<br/>(stampede-safe: конкурентные<br/>вызовы блокируются здесь)" --> L2

    subgraph DB_LAYER["L2: SQLite WAL"]
        L2["db::check_telega_id(pool, id)"]
        L2 --> L2_CHECK{"Запись в<br/>known_users?"}
        L2_CHECK -- "HIT" --> L2_RETURN["return Ok(true)<br/>→ кешируется на 24ч"]
    end

    L2_CHECK -- "MISS" --> L3

    subgraph API_LAYER["L3: Внешний API (calls.okcdn.ru)"]
        L3["api.check_id(telegram_id)"]
        L3 --> AUTH_CHECK{"session_key<br/>валиден?"}
        AUTH_CHECK -- "Нет / None" --> AUTH_ERR["LookupError::Auth"]
        AUTH_CHECK -- "Да" --> API_CALL["POST /api/vchat/<br/>getOkIdsByExternalIds"]
        API_CALL --> API_STATUS{"HTTP-статус?"}
        API_STATUS -- "401/403" --> REFRESH
        API_STATUS -- "429" --> BACKOFF["Экспоненциальный backoff<br/>1с → 2с → 4с → 8с<br/>(до 4 повторов)"]
        BACKOFF --> API_CALL
        API_STATUS -- "2xx" --> PARSE["Парсинг LookupResponse<br/>Сопоставление external_user_id.id"]
        API_STATUS -- "Другая ошибка" --> PROPAGATE["LookupError::Other<br/>→ проброс наверх"]

        subgraph SESSION_REFRESH["Double-Checked обновление сессии"]
            REFRESH["refresh_session(old_key)"]
            REFRESH --> LOCK{"Write lock:<br/>ключ изменился?"}
            LOCK -- "Уже обновлён<br/>другой задачей" --> SKIP["No-op (пропуск auth)"]
            LOCK -- "Устарел" --> REAUTH["POST /api/auth/<br/>anonymLogin"]
            REAUTH --> RETRY["Повтор запроса (однократно)"]
        end

        AUTH_ERR --> REFRESH
    end

    PARSE --> FOUND{"ID в<br/>response.ids?"}
    FOUND -- "true" --> PERSIST["db::save_telega_id(pool, id)<br/>INSERT OR IGNORE"]
    PERSIST --> CACHE_TRUE["return Ok(true)<br/>→ кеш 24ч TTL"]
    FOUND -- "false" --> CACHE_FALSE["return Ok(false)<br/>→ кеш 24ч TTL<br/>(негативный кеш)"]

    CACHE_TRUE --> LOG_REQ["db::log_request(user_hash, id, result)<br/>(псевдонимизировано)"]
    CACHE_FALSE --> LOG_REQ
    L1_RETURN --> LOG_REQ
    L2_RETURN --> LOG_REQ
    LOG_REQ --> RESPOND["Ответ в Telegram"]

    style CACHE_LAYER fill:#0a1628,stroke:#4488ff,stroke-width:2px,color:#ffffff
    style DB_LAYER fill:#1a1a00,stroke:#cccc44,stroke-width:2px,color:#ffffff
    style API_LAYER fill:#1a0a00,stroke:#ff8844,stroke-width:2px,color:#ffffff
    style SESSION_REFRESH fill:#2a0a1a,stroke:#ff44aa,stroke-width:1px,color:#ffffff
```

---

## Сравнительная матрица: официальный Telegram vs. Telega

| Параметр | Официальный Telegram | Форк Telega |
|---|---|---|
| **Диапазоны IP DC** | `149.154.167.x` (собственность Telegram) | `130.49.152.0/24` (AS203502, АО ТЕЛЕГА) |
| **Upstream AS** | Собственная инфраструктура Telegram | AS47764 (ООО ВК) -- единственный upstream-провайдер |
| **RSA-ключи (MTProto-хендшейк)** | 3 захардкоженных публичных ключа | 4 ключа; 4-й (`0x2c945714333b5ebd`) отклоняется Telegram DC, принимается прокси Telega |
| **Perfect Forward Secrecy** | Включён по умолчанию | Отключён (`usePfs: false` через конфиг `/v1/dc-proxy`) |
| **Секретные чаты** | Доступны; E2E через DH-2048 | Заблокированы: UI скрыт, входящие запросы молча отклоняются (`enable_sc: false`, Firebase Remote Config) |
| **Маршрутизация звонков** | Серверы Telegram (STUN/TURN) | `calls.okcdn.ru` / `api.ok.ru` (инфраструктура VK/Одноклассники) |
| **SSL-верификация звонков** | Стандартная проверка TLS-сертификатов | Отключена (`QuicClientConnectionImpl.java:1009`) |
| **DNS-разрешение** | Разрешено | Заблокировано клиентом |
| **Контроль хендшейка** | Сервер Telegram | Прокси-сервер Telega |
| **Принудительный повторный вход** | Не применимо | 4 удалённых триггера (push, deep link, промо-баннер) |
| **Незашифрованный HTTP** | Не разрешён | `android:usesCleartextTraffic="true"` в манифесте |
| **SSL Pinning** | Применяется для основных доменов | Отсутствует для `api.telega.info`, `calls.okcdn.ru`, `api.ok.ru` |
| **Телеметрия** | Стандартная аналитика Telegram | MyTracker (VK); передаёт статус VPN |
| **Запрашиваемые разрешения** | Минимальные для мессенджера | 75 разрешений (включая установку APK, фоновую геолокацию) |
| **Независимый аудит** | Протокол формально верифицирован (символьная модель, ScienceDirect 2023) | Аудит отсутствует; инфраструктура не верифицируема независимо |

---

## Метрики производительности: Python PoC vs. Rust

Теоретические проекции при устойчивой нагрузке. Python PoC предполагает `aiogram` 3.x на CPython 3.12 с `aiosqlite`. Rust-реализация использует стек из `Cargo.toml`: `teloxide` 0.17, `moka` 0.12, `sqlx` 0.8 (SQLite), `reqwest` 0.13 на `tokio` 1.x.

| Метрика | Python (`aiogram` + `aiosqlite`) | Rust (`teloxide` + `moka` + `sqlx`) |
|---|---|---|
| **L1 Cache Lookup (hot path)** | ~50-200 мкс (Python dict / `cachetools` TTLCache; ограничен GIL) | ~0.1-1 мкс (`moka` lock-free concurrent hash map) |
| **L2 SQLite Read** | ~200-800 мкс (`aiosqlite`; overhead thread-pool bridge) | ~10-50 мкс (`sqlx` + WAL mode; нативный async I/O, без GIL) |
| **L3 API Round-trip** | ~80-300 мс (сетевая задержка; идентично для обоих) | ~80-300 мс (сетевая задержка; идентично для обоих) |
| **Защита от cache stampede** | Требует ручной реализации (напр., `asyncio.Lock` на ключ) | Встроена через `moka::try_get_with` (per-key coalescing, zero-cost waiters) |
| **Конкурентная пропускная способность (L1 hits)** | ~2 000-5 000 req/s (GIL contention при доступе к кешу) | ~200 000-500 000 req/s (lock-free reads, без GIL) |
| **Конкурентная пропускная способность (L2 fallback)** | ~500-1 500 req/s (сериализация thread-pool) | ~20 000-50 000 req/s (async connection pool, 5 соединений) |
| **Память на 100K кешированных записей** | ~30-60 МБ (Python object overhead: 56+ байт/int, dict bucket) | ~3-6 МБ (i64 key + bool value + moka internal metadata) |
| **Размер бинарника / рантайма** | ~50 МБ (интерпретатор CPython + зависимости) | ~8-15 МБ (статически слинкованный release binary) |
| **Холодный старт (Docker)** | ~1-3 с (инициализация интерпретатора + импорт модулей) | ~10-50 мс (нативный бинарник, без инициализации рантайма) |
| **Макс. потребление памяти (idle)** | ~40-80 МБ | ~5-15 МБ |
| **Обновление сессии при контеншене** | Риск race condition без явной блокировки | Double-checked locking через `RwLock` (см. `refresh_session`) |

Задержка L3 определяется сетью и эквивалентна для обеих реализаций. Разница в производительности проявляется исключительно в пропускной способности hot-path L1/L2 и эффективности использования памяти при конкурентной нагрузке.

---

## Структура проекта

```
telega-checker-rs/
├── Cargo.toml              # Зависимости и метаданные пакета
├── Cargo.lock              # Воспроизводимое разрешение зависимостей
├── LICENSE                 # Лицензия Apache 2.0
├── Dockerfile              # Многоступенчатая сборка (rust:1.92-slim → debian:bookworm-slim)
├── docker-compose.yml      # Docker-топология: bot + cloudflared (Cloudflare Tunnel)
├── .env.example            # Шаблон переменных окружения
├── plugins/
│   ├── README.md                                # Документация плагинов (EN)
│   ├── README_RU.md                             # Документация плагинов (RU)
│   ├── telega_checker_rust_AyuGram.plugin        # Версия для AyuGram (инъекция TextDetailCell)
│   └── telega_checker_rust_exteraGram.plugin     # Версия для exteraGram (инъекция Badge)
├── docs/
│   ├── README_RU.md        # Русская версия README
│   └── DEPLOY.md           # Расширенная инструкция по развёртыванию
└── src/
    ├── main.rs             # Dual-Core точка входа: tokio::select!(Axum, Teloxide, Ctrl+C) с graceful shutdown
    ├── config.rs           # AppConfig: загрузка env-переменных + автогенерация pepper для аналитики
    ├── crypto.rs           # HMAC-SHA256 псевдонимизация для аналитики (усечённые 128-битные хеши)
    ├── api_server.rs       # Axum HTTP API: двойная Bearer-аутентификация, GET /api/check/:telegram_id
    ├── api_client.rs       # ApiClient: аутентификация + поиск через calls.okcdn.ru с обновлением сессии + экспоненциальный backoff 429
    ├── bot_handler.rs      # Telegram-обработчики: /start, /plugins, /upload_assets, /delete_asset, inline, отслеживание групп, callback-запросы
    ├── scheduler.rs        # Ежедневное cron-сканирование: возвращает хэндл для graceful shutdown; итерация по чатам, проверка участников
    └── db.rs               # Инициализация схемы SQLite, CRUD для known_users, chat_members, api_tokens, plugin_assets, псевдонимизированная аналитика
```

---

## Требования

- [Docker](https://docs.docker.com/get-docker/) и [Docker Compose](https://docs.docker.com/compose/install/)
- Токен Telegram-бота от [@BotFather](https://t.me/BotFather)
- Включённый inline-режим для бота (через BotFather: `/setinline`)
- Токен [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) для предоставления доступа к HTTP API

Для локальной разработки без Docker:
- Rust 1.92+ (edition 2024)
- `pkg-config` и `libssl-dev` (Debian/Ubuntu) или аналог для `native-tls`

---

## Конфигурация

Скопируйте шаблон и заполните обязательные значения:

```bash
cp .env.example .env
```

| Переменная | Обязательна | По умолчанию | Описание |
|---|---|---|---|
| `TELOXIDE_TOKEN` | Да | -- | Токен Telegram-бота от @BotFather |
| `DATABASE_URL` | Да | `sqlite:telega_checker.db?mode=rwc` | Строка подключения SQLite. В Docker переопределяется на `/app/data/telega_checker.db` через `docker-compose.yml`. |
| `APPLICATION_KEY` | Нет | `CHKIPMKGDIHBABABA` | Ключ приложения OK.ru API для аутентификации на `calls.okcdn.ru` |
| `API_BEARER_TOKEN` | Да | -- | Статический Bearer-токен для HTTP API аутентификации (обратная совместимость; также принимает per-user токены) |
| `API_PORT` | Нет | `8080` | Порт для Axum HTTP API-сервера |
| `DATABASE_MAX_CONNECTIONS` | Нет | `5` | Максимальный размер пула соединений SQLite. Увеличьте для развёртываний с большим количеством конкурентных сканирований групп. |
| `ADMIN_ID` | Да | -- | Telegram user ID администратора бота. Необходим для команд администратора (`/upload_assets`, `/delete_asset`). |
| `CLOUDFLARE_TUNNEL_TOKEN` | Да (Docker) | -- | Токен Cloudflare Tunnel для сервиса `cloudflared`. Сгенерируйте в Cloudflare Zero Trust Dashboard → Networks → Tunnels. |
| `RUST_LOG` | Нет | `info` | Директива фильтра трейсинга. `debug` для подробного вывода, `warn` для production. |

**Автогенерируемый файл:** При первом запуске приложение создаёт файл `.analytics_key`, содержащий криптографический pepper (два конкатенированных UUID v4) для HMAC-SHA256 псевдонимизации аналитических данных. Файл размещается в той же директории, что и база данных SQLite, и должен сохраняться между перезапусками для обеспечения консистентности псевдонимизированных идентификаторов. См. [Приватность и псевдонимизация аналитики](#приватность-и-псевдонимизация-аналитики).

---

## Развёртывание

### Docker (рекомендуется)

Production-топология состоит из двух Docker-сервисов:

| Сервис | Образ | Порты (хост) | Роль |
|---|---|---|---|
| `bot` | build: `.` | Нет (внутренний) | Dual-Core Rust-приложение (Telegram-бот + HTTP API на :8080) |
| `cloudflared` | `cloudflare/cloudflared:latest` | Нет | Cloudflare Tunnel — безопасное исходящее соединение с edge-сетью Cloudflare |

#### Перед развёртыванием

1. **Cloudflare Tunnel**: создайте туннель в [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/) → Networks → Tunnels. Настройте маршрутизацию трафика домена на `http://bot:8080`. Скопируйте токен туннеля в `.env` как `CLOUDFLARE_TUNNEL_TOKEN`.
2. **Cloudflare DNS**: направьте домен на туннель (автоматически настраивается при создании маршрута туннеля).
3. **SSL-сертификаты не требуются**: Cloudflare обрабатывает SSL-терминацию на edge. Никаких origin-сертификатов, Nginx или проброса портов.

```bash
# Сборка и запуск в фоновом режиме
docker compose up -d --build
```

Первая сборка компилирует полное дерево зависимостей Rust (~3-5 минут). Последующие сборки используют кеширование Docker-слоёв и завершаются за секунды, если `Cargo.toml` или `Cargo.lock` не изменились.

```bash
# Просмотр логов в реальном времени
docker compose logs -f

# Остановка (сохраняет том SQLite)
docker compose down

# Остановка и удаление всех данных
docker compose down -v
```

Именованный том `bot_data` монтируется в `/app/data` внутри контейнера. База данных SQLite и файл `.analytics_key` сохраняются между циклами `down` + `up`.

| Том | Путь в контейнере | Содержимое |
|---|---|---|
| `bot_data` | `/app/data` | `telega_checker.db`, `*.db-wal`, `*.db-shm`, `.analytics_key` |

### Локальная разработка

```bash
# Убедитесь, что .env заполнен (включая API_BEARER_TOKEN и ADMIN_ID)
cargo run --release
```

Бинарник читает `.env` из рабочей директории через `dotenvy`. Telegram-бот и HTTP API-сервер запускаются параллельно. База данных SQLite создаётся по пути, указанному в `DATABASE_URL`.

### Детали Dockerfile

Dockerfile реализует двухступенчатую сборку:

1. **Стадия сборки** (`rust:1.92-slim-bookworm`): компиляция release-бинарника с кешированием зависимостей (трюк с dummy `main.rs` для раздельного кеширования скомпилированных зависимостей и кода приложения).
2. **Стадия рантайма** (`debian:bookworm-slim`): минимальный образ только с `ca-certificates` и `libssl3`. Копирует директорию `plugins/` в образ для команды администратора `/upload_assets`. Запускается от непривилегированного пользователя `appuser` (UID 1001). Выставляет порт `8080` для внутренней Docker-сети.

---

## Использование

### Личное сообщение

Отправьте числовой Telegram ID боту:

```
123456789
```

Ответ:
- Присутствует в инфраструктуре Telega: `✅ ДА — этот ID зарегистрирован в Telega.`
- Не найден: `❌ НЕТ — этот ID не найден в Telega.`

### Inline-запрос

В любом чате Telegram введите:

```
@telega_checker_rs_bot 123456789
```

Результаты кешируются на стороне Telegram на 300 секунд (5 минут) через `cache_time`.

### Упоминание в группе

Когда бот добавлен в группу или супергруппу, вы можете проверить ID, упомянув бота:

```
@telega_checker_rs_bot 123456789
```

Бот ответит прямо в группе результатом проверки. Невалидные или пустые ID молча игнорируются для предотвращения спама.

### Команда /start

Отображает инструкции по использованию, ссылку на OSINT-статью о механизмах перехвата Telega и inline-кнопку для загрузки плагинов и получения персонального API-токена.

### Команда /plugins

Доступна только в личных сообщениях. Доставляет файлы плагинов как Telegram-документы (используя кешированный `file_id` для нулевой нагрузки на канал), генерирует или получает персональный API-токен пользователя и предоставляет инструкции по установке. Включает inline-кнопку «Сбросить API токен» для ротации токена.

### Команды администратора

Ограничены пользователем `ADMIN_ID`. Фильтрация на уровне диспетчера и внутри каждого обработчика (defense-in-depth).

| Команда | Описание |
|---|---|
| `/upload_assets` | Читает `.plugin` файлы из директории `plugins/`, загружает их в Telegram и сохраняет полученные `file_id` в таблице `plugin_assets` для последующей доставки с нулевой нагрузкой на канал. |
| `/delete_asset <имя>` | Удаляет конкретный плагин из базы данных по его производному имени (напр., `ayugram`). |

---

## HTTP API

Axum HTTP API-сервер предоставляет RESTful-эндпоинт для внешних клиентов (напр., Android-плагин). Работает на том же tokio-рантайме, что и Telegram-бот, и использует идентичный `AppState` — попадания в кеш со стороны бота приносят пользу API, и наоборот.

### Аутентификация

Все API-запросы требуют Bearer-токен в заголовке `Authorization`:

```
Authorization: Bearer <TOKEN>
```

Сервер принимает два типа токенов (двойная валидация):

1. **Статический токен** — переменная окружения `API_BEARER_TOKEN` (обратная совместимость, административное/тестовое использование).
2. **Per-user токены** — UUID v4 токены, генерируемые через команду `/plugins` и хранящиеся в таблице `api_tokens`. Каждый пользователь получает уникальный токен, привязанный к его Telegram-аккаунту, с возможностью ротации через кнопку «Сбросить API токен».

Запросы без валидного токена получают ответ `401 Unauthorized`.

### Эндпоинт

#### `GET /api/check/:telegram_id`

Проверяет, зарегистрирован ли Telegram user ID в инфраструктуре Telega.

**Успех (200):**
```json
{"telegram_id": 123456789, "is_compromised": true}
```

**Невалидный ID (400):**
```json
{"error": "Invalid telegram_id 'abc'. Must be a positive integer."}
```

**Ошибка аутентификации (401):**
```json
{"error": "Invalid bearer token"}
```

**Ошибка сервера (500):**
```json
{"error": "Internal lookup error. Please try again later."}
```

### Пример

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" https://tc.berektassuly.com/api/check/123456789
```

### Rate Limiting

Rate limiting обрабатывается на edge-уровне Cloudflare через WAF-правила или Cloudflare Rate Limiting, заменяя предыдущий подход на базе Nginx.

---

## Пассивный мониторинг групп

При добавлении в группу или супергруппу бот работает бесшумно как пассивный монитор.

### Принцип работы

1. **Автоматическое отслеживание**: бот наблюдает за всеми сообщениями и событиями входа/выхода. Команды не нужны — просто добавьте бота в группу.
2. **Ежедневное сканирование в 09:00 UTC**: бот проверяет каждого отслеживаемого участника через трёхуровневый поиск (moka → SQLite → okcdn.ru API).
3. **Отчёт при обнаружении**: если обнаружены скомпрометированные аккаунты, бот отправляет единый отчёт:

```
Daily Scan Report

The following members are using the compromised Telega client:

1. User
2. User
```

4. **Тишина при чистых результатах**: если пользователей Telega не найдено, сообщение не отправляется.
5. **Самоочистка**: если бот удалён из группы, он автоматически деактивирует все записи отслеживания для этой группы.

### Требования к группе

- Бот должен иметь разрешение на чтение сообщений в группе.
- Права администратора не требуются — бот только читает и отправляет сообщения.
- Бот отслеживает пользователей пассивно; он не банит, не мьютит и не ограничивает никого.

### Хранение данных

Отслеживание использует модель мягкого удаления. Когда пользователь покидает группу или бот удалён, записи помечаются `is_active = FALSE` вместо удаления. Это сохраняет историческую аналитику, исключая неактивных участников из будущих сканирований.

---

## Схема базы данных

SQLite с включённым WAL-режимом (`PRAGMA journal_mode=WAL`) для конкурентной производительности чтения.

### `known_users` (функционально необходима)

Персистентный L2-кеш Telegram ID, подтверждённых как присутствующие в инфраструктуре Telega.

```sql
CREATE TABLE IF NOT EXISTS known_users (
    telegram_id  INTEGER PRIMARY KEY,
    discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### `bot_users` (псевдонимизированная аналитика)

Отслеживает пользователей, взаимодействовавших с ботом, через усечённые HMAC-SHA256 хеши. Сырые Telegram user ID и имена пользователей не хранятся.

```sql
CREATE TABLE IF NOT EXISTS bot_users (
    user_hash  TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### `requests_log` (псевдонимизированная аналитика)

Append-only журнал всех событий поиска. Использует тот же HMAC-SHA256 псевдонимизированный идентификатор, что и `bot_users`.

```sql
CREATE TABLE IF NOT EXISTS requests_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_hash  TEXT    NOT NULL,
    queried_id INTEGER NOT NULL,
    result     TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
```

### `chat_members` (пассивный мониторинг)

Отслеживает присутствие пользователей в группах. Использует паттерн мягкого удаления (`is_active`) для сохранения истории.

```sql
CREATE TABLE IF NOT EXISTS chat_members (
    chat_id   INTEGER NOT NULL,
    user_id   INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (chat_id, user_id)
);
```

### `api_tokens` (per-user доступ к API)

Хранит per-user API-токены для аутентифицированного доступа к HTTP API. Каждый пользователь получает UUID v4 токен при первом запросе `/plugins`, с поддержкой ротации токена.

```sql
CREATE TABLE IF NOT EXISTS api_tokens (
    user_id    INTEGER PRIMARY KEY,
    api_token  TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### `plugin_assets` (доставка плагинов)

Персистентное хранилище Telegram `file_id` загруженных файлов плагинов. Обеспечивает повторную доставку плагинов с нулевыми затратами трафика через ссылки на кешированные файлы на серверах Telegram.

```sql
CREATE TABLE IF NOT EXISTS plugin_assets (
    name       TEXT PRIMARY KEY,
    file_id    TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

---

## Приватность и псевдонимизация аналитики

Все аналитические таблицы (`bot_users`, `requests_log`) хранят псевдонимизированные идентификаторы вместо сырых Telegram user ID или имён пользователей. Реализовано через схему **zero-knowledge HMAC-SHA256**:

1. **Генерация pepper**: при первом запуске приложение генерирует криптографический pepper (два конкатенированных UUID v4, 72 символа энтропии) и сохраняет его в `.analytics_key` рядом с базой данных SQLite. Этот файл должен сохраняться между перезапусками.

2. **Хеширование**: каждый Telegram user ID преобразуется через `HMAC-SHA256(pepper, user_id_bytes)`, затем усекается до 32 hex-символов (128 бит). Одна и та же пара `(user_id, pepper)` всегда даёт одинаковый хеш, сохраняя аналитическую консистентность.

3. **Свойства**:
   - **Детерминистичность**: повторные взаимодействия одного пользователя дают одинаковый хеш, обеспечивая статистику использования и дедупликацию.
   - **Необратимость**: pepper никогда не передаётся через API или команды бота. Без pepper хеши не могут быть обращены в Telegram ID.
   - **Zero-knowledge**: оператор может наблюдать паттерны использования без идентификации конкретных пользователей.

Модуль `crypto.rs` реализует функцию хеширования. Pepper загружается с диска через `config.rs` и внедряется в `AppState` для использования всеми обработчиками.

---

## Заметки по операционной безопасности

Таблицы `bot_users` и `requests_log` предоставлены для операционной аналитики (статистика использования, отладка, принятие решений по rate-limiting). Они не требуются для основного функционала детектирования. Единственная таблица, необходимая для корректной работы трёхуровневого поиска -- `known_users`.

Операторы, развёртывающие бот в средах с приоритетом минимизации метаданных, могут отключить аналитическое логирование, удалив или закомментировав вызовы `db::log_request()` и `db::log_bot_user()` в `src/bot_handler.rs`. Это простая модификация, ограниченная точками вызова в `handle_message`, `handle_inline_query` и `handle_mention_lookup`.

Альтернативный подход для операторов, которым нужна аналитика при разработке, но не в production: введение feature-флага Cargo (напр., `analytics`), условно компилирующего код логирования. Пример добавления в `Cargo.toml`:

```toml
[features]
default = []
analytics = []
```

Затем оберните вызовы логирования в `#[cfg(feature = "analytics")]` и компилируйте с `cargo build --release --features analytics` только при необходимости.

Для эфемерных развёртываний, где данные не должны сохраняться между перезапусками, смонтируйте том SQLite как `tmpfs`:

```yaml
volumes:
  - type: tmpfs
    target: /app/data
```

Учтите, что это также делает L2-кеш (`known_users`), pepper для аналитики (`.analytics_key`) и per-user API-токены (`api_tokens`) эфемерными, вынуждая все запросы обращаться к L3 до повторного заполнения кеша и выпуска новых токенов при каждом перезапуске.

---

## Клиентские плагины

Android-плагины для AyuGram и exteraGram, использующие HTTP API для отображения индикаторов статуса Telega в реальном времени. Каждый плагин внедряется в UI клиента через рефлексию Java и перехват методов, выполняет асинхронные HTTPS-запросы к бэкенду и кеширует результаты локально (TTL 6 часов).

| Клиент | Версия | Скачать |
|---|---|---|
| **AyuGram** | v1.1.0 | [Скачать плагин](https://github.com/Berektassuly/telega-checker-rs/raw/main/plugins/telega_checker_rust_AyuGram.plugin) |
| **exteraGram** | v1.1.0 | [Скачать плагин](https://github.com/Berektassuly/telega-checker-rs/raw/main/plugins/telega_checker_rust_exteraGram.plugin) |

Полная документация — архитектура, установка, конфигурация, анализ безопасности и сравнение функций по клиентам — в [README плагинов](../plugins/README_RU.md).

---

## Лицензия

Этот проект лицензирован под [Apache License 2.0](../LICENSE).
