# HoneyForge — Технический дизайн-документ (MVP)

> Статус: черновик v0.1 · Дата: 2026-10-10
> Опирается на «План реализации стенда киберполигона». Этот документ фиксирует **как** строим то, что план описывает на уровне **что**.
> Границы стенда (из плана, раздел 6) действуют всегда: только изолированная лаб-сеть/DMZ, всё синтетическое, маскировка — имитация легитимного трафика *для атакующего внутри стенда*, не для сокрытия от владельца/администраторов.

---

## 1. Выбор стека и обоснования

| Контур | Технология | Почему именно так |
|---|---|---|
| Control API (центр) | **Python 3.12 + FastAPI** | Один язык с агентом и ловушками; авто-Swagger (нужен для демо FR-C1/C2); async. |
| ORM + миграции | **SQLAlchemy 2.x + Alembic** | Воспроизводимость схемы (DoD: чистый запуск без ручных правок). |
| Хранилище | **PostgreSQL 16** | Требование плана; JSONB для гибкой телеметрии. |
| Realtime | **FastAPI WebSocket + Redis Pub/Sub** | См. ADR-1 ниже — отход от «Node.js» из плана, осознанный. |
| Очередь/шина | **Redis 7** | Pub/Sub для realtime + буфер/дедуп на приёме телеметрии. |
| Агент | **Python 3.12** (один бинарь/контейнер) | Общий код с ловушками; локальный буфер на SQLite. |
| Low-ловушка | **Python asyncio** (TCP/UDP listeners) | Лёгкая эмуляция баннеров без тяжёлых зависимостей. |
| Medium-ловушка | **asyncssh** (fake-SSH) + FastAPI (fake-HTTP-админка) | asyncssh даёт серверный SSH с перехватом auth и команд. |
| Dashboard | **React + Vite + TypeScript + Chart.js** | Плана требует конструктор профилей + графики; Vite быстр в сборке. |
| Reverse-proxy / TLS | **Nginx** | TLS-терминация, маскировка collector под веб-ресурс, разделение vhost'ов. |
| Оркестрация | **docker-compose** | Требование плана; воспроизводимость. |

### ADR-1. Realtime на FastAPI вместо Node.js
План (3.1.6) предлагает отдельный Node.js-сервис под WebSocket. Для команды 1–2 человека это лишний язык, сборка и деплой. **Решение:** realtime держим в том же FastAPI-процессе (или воркере), события текут через `Redis Pub/Sub`: коллектор публикует событие в канал → WebSocket-эндпоинт ретранслирует подписанным операторам. Плюсы: один язык, одна кодовая база, проще тесты. Если на защите потребуют именно Node.js — вынос тривиален, т.к. контракт события уже проходит через Redis (§6.3), а не через прямой вызов.

### ADR-2. Коллектор телеметрии — модуль, а не отдельный сервис (на Must)
На спринтах 2–4 коллектор — это набор роутов внутри FastAPI, но **логически и по сети** он отделён: слушает только на «публичном» (honeynet-facing) интерфейсе через отдельный Nginx-vhost с замаскированным путём, тогда как операторский API доступен только из mgmt-сети. Разделение обеспечивается Nginx + docker-сетями (§4), а не разными процессами. Это закрывает MASK-2/MASK-3 на Must-уровне без оверинжиниринга.

### ADR-3. Агент и ловушка — раздельные процессы, общий контейнер-образ
Агент (телеметрия/конфиг/буфер) и сама ловушка (сервисы-приманки) — разные ответственности. Агент общается с центром; ловушка общается с атакующим. В одном хосте ловушки они упакованы в один образ, но запускаются как отдельные процессы (supervisor / две docker-команды), чтобы падение ловушки не роняло дослылку буфера.

---

## 2. Структура репозитория

```
HoneyForge_rep/
├─ docker-compose.yml              # весь стек (центр + pg + redis + nginx + 2 ловушки)
├─ docker-compose.override.yml     # dev-оверрайды (hot-reload, порты наружу)
├─ .env.example                    # шаблон секретов (реальный .env в .gitignore)
├─ README.md
├─ docs/
│  ├─ DESIGN.md                    # этот документ
│  ├─ architecture.excalidraw      # схема архитектуры (спринт 6)
│  └─ db-schema.md                 # ER-диаграмма
├─ center/                         # Control API + коллектор + realtime
│  ├─ pyproject.toml
│  ├─ app/
│  │  ├─ main.py                   # сборка FastAPI, роутеры, lifespan
│  │  ├─ config.py                 # Pydantic Settings из env
│  │  ├─ db/
│  │  │  ├─ base.py                # engine, session
│  │  │  └─ models.py              # SQLAlchemy модели (§5)
│  │  ├─ alembic/                  # миграции
│  │  ├─ api/
│  │  │  ├─ operator/              # mgmt-API (auth, profiles, honeypots, events)
│  │  │  └─ agent/                 # agent-API (enroll, config, ingest) — маскируемый
│  │  ├─ realtime/                 # WebSocket + подписка на Redis
│  │  ├─ schemas/                  # Pydantic DTO (контракты §6)
│  │  ├─ services/                 # бизнес-логика (нормализация, алерты, IoC)
│  │  └─ security/                 # JWT, пароли, enrollment-токены, (mTLS на bonus)
│  └─ tests/
├─ agent/                          # агент ловушки
│  ├─ pyproject.toml
│  └─ honeyagent/
│     ├─ main.py                   # цикл: config-pull → beacon → flush-buffer
│     ├─ buffer.py                 # локальная SQLite-очередь (FR-A4)
│     ├─ transport.py              # HTTPS-клиент к замаскированному endpoint
│     └─ collectors/               # сбор событий от ловушек (unix socket / localhost)
├─ honeypots/
│  ├─ common/                      # формат события, отправка агенту
│  ├─ low/                         # TCP/UDP баннеры (FR-A1 Low)
│  │  └─ main.py
│  └─ medium/                      # fake-SSH / fake-HTTP / fake-DB (FR-A1 Medium)
│     ├─ ssh_server.py
│     ├─ http_admin.py
│     └─ fake_fs.py                # синтетическая ФС для сессии
├─ dashboard/                      # React + Vite
│  ├─ package.json
│  └─ src/
│     ├─ pages/ (Login, Honeypots, HoneypotDetail, Events, ProfileBuilder, Analytics)
│     ├─ api/   (клиент mgmt-API + ws)
│     └─ components/
├─ nginx/
│  ├─ nginx.conf
│  ├─ sites/
│  │  ├─ mgmt.conf                 # операторский API+dashboard (только mgmt-сеть)
│  │  └─ public.conf               # замаскированный collector (honeynet-facing)
│  └─ certs/                       # самоподписанные для dev (в .gitignore)
└─ scripts/
   ├─ gen-certs.sh                 # генерация TLS-сертов для dev
   ├─ seed.py                      # демо-оператор + профили (креды в seed, не в чат)
   └─ attack-demo.sh              # сценарий «атака → событие» для защиты
```

---

## 3. Компонентная архитектура

```
             ┌────────────────────── mgmt-сеть (внутренняя) ───────────────────────┐
             │                                                                      │
 оператор ──TLS──▶ Nginx(mgmt.conf) ──▶ Control API (FastAPI) ──▶ PostgreSQL        │
   (браузер)         │  dashboard SPA        │   ▲        │                          │
                     └── WebSocket ──────────┘   │        └──▶ Redis (pub/sub,buffer)│
             └──────────────────────────────────┼───────────────────────────────────┘
                                                 │ (публикация событий)
             ┌─────────────────── honeynet (сегмент приманки) ──────────────────────┐
             │                                   │                                   │
  атакующий ─scan/ssh/http─▶  [ Low HP ] [ Medium HP ]                               │
             │                     │  localhost/socket  │                            │
             │                     └──────▶ Агент ──TLS(beacon)──▶ Nginx(public.conf) ┘
             │                                              «похоже на CDN/аналитику»  │
             └───────────────────────────────────────────────────────────────────────┘
```

Ключевые инварианты:
- Операторский API **недоступен** из honeynet (разные docker-сети + Nginx-разделение).
- Агент знает только публичный замаскированный URL, никогда — адрес БД/mgmt.
- Атакующий видит только ловушки и «обычный веб-ресурс» (collector за Nginx).

---

## 4. Сетевая сегментация (docker networks)

Две сети в `docker-compose.yml`:

- **`mgmt`** (internal: true) — `postgres`, `redis`, `center`, `dashboard`(статика через nginx), `nginx-mgmt`. Не имеет выхода, кроме проброса операторского порта на хост-машину оператора.
- **`honeynet`** — `honeypot-low`, `honeypot-medium`, `agent`, `nginx-public`. Это сегмент, «видимый атакующему».

Мост между ними — **только** через collector: `nginx-public` принимает телеметрию в honeynet и проксирует её на `center` по mgmt. Center подключён к обеим сетям, но:
- слушает операторские роуты на интерфейсе mgmt,
- принимает агентские роуты на интерфейсе, доступном из honeynet через `nginx-public`.

На Bonus (спринт 5) `nginx-public` и `nginx-mgmt` — разные контейнеры/хосты; на Must допустимо два server-блока одного Nginx с разными upstream и ACL. MASK-3 выполняется тем, что из honeynet физически нет маршрута к `postgres`/операторскому порту.

---

## 5. Схема БД

Диалект PostgreSQL. Миграции — Alembic. JSONB для расширяемых деталей событий.

```sql
-- Операторы (FR-C5)
operators(
  id            uuid pk,
  username      text unique not null,
  password_hash text not null,          -- argon2
  role          text not null default 'operator',  -- operator|admin
  created_at    timestamptz not null default now()
)

-- Профили ловушек (FR-C1)
profiles(
  id            uuid pk,
  name          text not null,
  level         text not null,          -- low|medium|high
  config        jsonb not null,         -- порты, баннеры, сервисы, креды-приманки, логирование, маскировка
  created_by    uuid fk->operators.id,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
)

-- Зарегистрированные ловушки (FR-C2)
honeypots(
  id            uuid pk,
  name          text not null,
  profile_id    uuid fk->profiles.id,
  enroll_token_hash text not null,      -- хэш токена привязки
  agent_key_hash    text,               -- выданный агенту секрет (на mTLS->bonus)
  status        text not null default 'unknown', -- online|offline|unknown
  last_seen_at  timestamptz,
  host_label    text,                   -- неприметная метка хоста (не 'honeypot-1')
  created_at    timestamptz not null default now()
)

-- События атак (FR-C4) — главная таблица телеметрии
events(
  id            bigserial pk,
  honeypot_id   uuid fk->honeypots.id,
  event_type    text not null,          -- scan|connect|auth_attempt|command|http_request|token_trigger
  source_ip     inet,
  source_port   int,
  dest_port     int,
  protocol      text,                   -- tcp|udp|ssh|http
  severity      text not null default 'info',  -- info|low|medium|high
  session_id    uuid fk->sessions.id null,
  payload       jsonb not null default '{}',   -- детали: баннер, путь, UA, команда и т.д.
  occurred_at   timestamptz not null,   -- время на ловушке
  received_at   timestamptz not null default now(),  -- время приёма центром
  dedup_key     text unique             -- идемпотентность дослылки из буфера (FR-A4)
)
-- индексы: (honeypot_id, occurred_at), (source_ip), (event_type)

-- Интерактивные сессии (Medium, FR-A1/A2)
sessions(
  id            uuid pk,
  honeypot_id   uuid fk->honeypots.id,
  service       text not null,          -- ssh|http|db
  source_ip     inet,
  started_at    timestamptz not null,
  ended_at      timestamptz,
  meta          jsonb not null default '{}'
)

-- Попытки аутентификации (креды маскируются, FR-A2)
auth_attempts(
  id            bigserial pk,
  session_id    uuid fk->sessions.id,
  honeypot_id   uuid fk->honeypots.id,
  username      text,                   -- логин сохраняем
  password_hash text,                   -- пароль НЕ в открытом виде: hash/mask
  password_preview text,                -- напр. 'p****d' для аналитики
  success       bool not null default false,
  occurred_at   timestamptz not null
)

-- Артефакты (загруженные файлы/дампы сессий, bonus/High)
artifacts(
  id            uuid pk,
  honeypot_id   uuid fk->honeypots.id,
  session_id    uuid fk->sessions.id null,
  kind          text,                   -- pcap|session_log|upload
  path          text,                   -- путь в object-store/томе
  sha256        text,
  created_at    timestamptz not null default now()
)

-- Honeytokens (Bonus, FR-A6)
honeytokens(
  id            uuid pk,
  profile_id    uuid fk->profiles.id,
  kind          text,                   -- aws_key|url|doc|canary
  value_ref     text,                   -- идентификатор, не сам секрет
  triggered_at  timestamptz,
  trigger_meta  jsonb
)

-- Аудит действий оператора (FR-C5 / наблюдаемость)
audit_log(
  id            bigserial pk,
  operator_id   uuid fk->operators.id,
  action        text not null,          -- login|profile.create|honeypot.deploy|...
  target        text,
  detail        jsonb,
  ip            inet,
  created_at    timestamptz not null default now()
)
```

Формат `profiles.config` (пример Medium):
```json
{
  "services": [
    {"type": "ssh",  "port": 22,  "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
     "fake_credentials": [{"username": "admin", "password": "admin123"}],
     "fake_fs": "ubuntu-minimal"},
    {"type": "http", "port": 80,  "server_header": "nginx/1.24.0",
     "admin_path": "/admin", "login_template": "generic"}
  ],
  "logging": {"capture_commands": true, "mask_passwords": true},
  "masking": {"beacon_jitter_s": [20, 40], "process_name": "systemd-timesyncd"}
}
```

---

## 6. API-контракты

Два независимых поверхностных API. Разные базовые пути, разная аутентификация, **разная сетевая экспозиция**.

### 6.1 Операторский API (mgmt) — префикс `/api/v1`, только из mgmt-сети

Аутентификация: JWT (access + refresh), пароль через Argon2. Все роуты, кроме `/auth/login`, требуют `Authorization: Bearer`.

```
POST   /api/v1/auth/login            {username, password} -> {access_token, refresh_token}
POST   /api/v1/auth/refresh          {refresh_token}      -> {access_token}
GET    /api/v1/me                                           -> {id, username, role}

# Профили (FR-C1)
GET    /api/v1/profiles                                     -> [Profile]
POST   /api/v1/profiles              ProfileCreate          -> Profile
GET    /api/v1/profiles/{id}                                -> Profile
PUT    /api/v1/profiles/{id}         ProfileUpdate          -> Profile
DELETE /api/v1/profiles/{id}                                -> 204

# Ловушки (FR-C2)
GET    /api/v1/honeypots                                     -> [Honeypot]  # со status/last_seen
POST   /api/v1/honeypots             {name, profile_id, host_label}
                                                            -> {honeypot, enroll_token}  # токен показывается один раз
GET    /api/v1/honeypots/{id}                                -> HoneypotDetail
DELETE /api/v1/honeypots/{id}                                -> 204

# События (FR-C4) — фильтры по ловушке/времени/источнику/типу
GET    /api/v1/events?honeypot_id=&type=&source_ip=&from=&to=&limit=&cursor=
                                                            -> {items:[Event], next_cursor}
GET    /api/v1/sessions/{id}                                -> SessionDetail (+ commands, auth_attempts)

# Аналитика (dashboard §3.4.4)
GET    /api/v1/stats/summary                                -> {total_events, by_type, top_sources, timeline}

# Bonus
POST   /api/v1/honeypots/{id}/deploy                         -> запуск оркестратора (FR-C6)
GET    /api/v1/export/iocs?format=csv|stix                   -> файл (FR-C7)
GET    /api/v1/audit                                         -> [AuditEntry]
```

### 6.2 Агентский API (маскируемый, honeynet-facing)

**Важно (MASK-2):** снаружи пути выглядят как обычный веб-ресурс. Внутри Nginx (`public.conf`) переписывает их на внутренние роуты центра. Пример отображения:

| Внешний (виден атакующему) | Внутренний роут центра | Назначение |
|---|---|---|
| `POST /assets/v3/collect`        | `/agent/telemetry` | приём телеметрии (beacon + события) |
| `GET  /assets/v3/manifest.json`  | `/agent/config`    | выдача конфигурации по профилю (FR-C3) |
| `POST /assets/v3/register`       | `/agent/enroll`    | привязка ловушки по enroll-токену |

Аутентификация агента: на Must — `enroll_token` → в ответ выдаётся `agent_key`; дальше каждый запрос подписан `agent_key` (HMAC-заголовок, выглядящий как обычный `X-Request-Id`/cookie). На Bonus (MASK-7) — mTLS с pinning + ротация.

Контракт телеметрии (тело `POST /assets/v3/collect`, по TLS, MASK-1):
```json
{
  "agent_id": "uuid",
  "sent_at": "2026-10-10T12:00:00Z",
  "beacon": {"uptime_s": 3600, "hp_status": "ok"},
  "events": [
    {
      "dedup_key": "uuid-or-hash",      // идемпотентность дослылки (FR-A4)
      "event_type": "auth_attempt",
      "occurred_at": "2026-10-10T11:59:58Z",
      "source_ip": "10.0.5.7", "source_port": 51234, "dest_port": 22,
      "protocol": "ssh", "session_id": "uuid",
      "payload": {"username": "root", "password_masked": "t****3"}
    }
  ]
}
```
Ответ: `{ "accepted": N, "next_poll_s": 30, "config_etag": "..." }` — `config_etag` сигналит агенту, что пора забрать свежий `manifest.json` (конфиг).

### 6.3 Внутренний контракт realtime (Redis → WS)
Коллектор после записи события публикует в канал `events:{honeypot_id}` и `events:all`:
```json
{"type":"event","data":{Event}}      // оператор подписан через WS /api/v1/ws?token=JWT
{"type":"honeypot_status","data":{"id":"...","status":"online","last_seen_at":"..."}}
```
WebSocket-эндпоинт проверяет JWT при хендшейке, затем стримит из Redis-подписки.

---

## 7. Потоки данных (ключевые сценарии)

**Регистрация ловушки:** оператор создаёт профиль → создаёт honeypot (получает `enroll_token`, показан один раз) → токен кладётся в env агента на хосте ловушки → агент `POST /assets/v3/register` → получает `agent_id` + `agent_key` + конфиг → статус `online`.

**Событие атаки:** атакующий сканирует/логинится → ловушка формирует событие → шлёт агенту (localhost/unix-socket) → агент кладёт в SQLite-буфер → по beacon-циклу `POST /assets/v3/collect` по TLS → Nginx(public) → center `/agent/telemetry` → нормализация + запись в `events` (idempotent по `dedup_key`) → публикация в Redis → WS → лента dashboard (near-real-time).

**Потеря связи (FR-A4):** центр недоступен → агент продолжает писать в SQLite-буфер → при восстановлении досылает пачками; `dedup_key` исключает дубли. Статус ловушки станет `offline` по истечении `last_seen` TTL, затем снова `online`.

**Рестарт центра (DoD):** данные в PostgreSQL-томе переживают рестарт; Redis — только транспорт, потеря его содержимого некритична.

---

## 8. Безопасность и маскировка — трассировка к требованиям

| Требование | Реализация в этом дизайне |
|---|---|
| MASK-1 TLS | Nginx TLS-терминация на обоих vhost; агент ходит только по HTTPS. |
| MASK-2 неприметный endpoint | `/assets/v3/*` под видом CDN/аналитики; внутренний рерайт в Nginx; никаких `honeypot`/`c2` в путях. |
| MASK-3 разделение интерфейсов | docker-сети `mgmt`(internal) vs `honeynet`; из honeynet нет маршрута к БД/операторскому порту. |
| MASK-4 скрытность агента | `process_name` из профиля (напр. `systemd-timesyncd`), неприметный путь, без строк-маркеров. |
| MASK-5 джиттер (Bonus) | `beacon_jitter_s` рандомизирует интервал маяка. |
| MASK-6 анти-фингерпринтинг (Bonus) | рандомизация баннеров/таймингов/ошибок в ловушках. |
| MASK-7 mTLS (Bonus) | взаимный TLS с клиентскими сертификатами, pinning CA и ротацией. Реализовано, toggleable. См. примечание ниже. |

> **MASK-7 (реализовано, toggleable).** Полный mTLS включается оверлеем
> `docker-compose.mtls.yml` (`MTLS_ENABLED=true`). Как снят конфликт с
> маскировкой под CDN (MASK-2): на коллекторе `ssl_verify_client **optional**` —
> обложка-страница и случайные посетители работают без сертификата (обычный CDN),
> а клиентский сертификат **требуется только на агентских путях** `/assets/v3/*`
> (nginx: `if ($ssl_client_verify != SUCCESS) return 403`). Таким образом mTLS есть,
> но mTLS-челлендж видят только агенты, не прохожие.
>
> - **CA.** `cert-init` генерирует локальный CA (`ca.crt`/`ca.key`) и
>   server-сертификат, подписанный CA. Центр держит `ca.key` и выпускает
>   короткоживущие клиентские сертификаты (CN = agent_id).
> - **Bootstrap.** `enroll` не требует клиентского сертификата (защищён
>   enroll-токеном) — в ответе агент получает `ca_cert` + `client_cert`/`client_key`.
> - **Pinning.** После enroll агент проверяет сервер против полученного CA
>   (`verify=ca.crt`), а не системного доверия, и предъявляет клиентский сертификат
>   на `collect`/`manifest`/`renew`.
> - **Ротация.** Перед истечением агент дёргает `/assets/v3/renew` (→ `/agent/rotate`)
>   и получает свежий сертификат. Плюс сохраняется ротация `agent_key` при каждом enroll.
>
> По умолчанию (демо/прод) mTLS выключен — чтобы не усложнять запуск и сохранить
> чистую легенду; включается одним оверлеем для изолированного стенда.
| FR-C5 auth | JWT + Argon2 + `audit_log`; неаутентифицированный доступ к mgmt-API закрыт. |
| Секреты | только из `.env`/secret-store; `.env`, `nginx/certs/` в `.gitignore`; креды-приманки в `scripts/seed.py`, не в чат и не в README. |

---

## 9. План по спринтам → артефакты кода

- **Спринт 0:** `docker-compose.yml`, скелеты `center/`, Nginx, healthcheck `/healthz`, `.env.example`, `scripts/gen-certs.sh`.
- **Спринт 1:** модели + Alembic, auth (JWT), profiles CRUD, honeypots register/list, Swagger, `scripts/seed.py`.
- **Спринт 2:** агент (config-pull/beacon/buffer), Low-ловушка, agent-API + Nginx `public.conf` (маскировка), TLS, запись `events`.
- **Спринт 3:** Redis pub/sub, WS-эндпоинт, dashboard: список ловушек + живая лента + фильтры.
- **Спринт 4:** Medium-ловушка (asyncssh + fake-HTTP + fake-FS), `sessions`/`auth_attempts`, карточка сессии, `scripts/attack-demo.sh`.
- **Спринт 5–6 (Bonus):** оркестратор deploy, джиттер/анти-фингерпринт, mTLS, алерты, IoC-экспорт, honeytokens, High-interaction, README/схемы/презентация.

---

## 10. Принятые решения (зафиксировано 2026-10-10)

1. **Dashboard:** React + Vite + TypeScript + Chart.js.
2. **Medium fake-SSH:** `asyncssh` (async, единый стиль с остальным кодом).
3. **Замаскированный путь:** легенда «CDN статики» — `/assets/v3/*` (collect / manifest.json / register), см. §6.2.
4. **Оркестратор (Bonus):** деплой через локальный Docker API на той же машине (демо); удалённый деплой по SSH — план развития.
5. **High-interaction:** в рамках сдачи — **план развития** (не строим), НО архитектуру готовим под простое подключение реальной ОС позже (см. §11).

## 11. High-interaction (реализовано, lab-only)

Реализован как fake-SSH (`honeypots/high/ssh_server.py`, тип сервиса `ssh_high`),
где команды атакующего **выполняются по-настоящему** в одноразовой песочнице:

- **одноразовый контейнер на сессию** (`docker run --rm`), уничтожается при
  отключении — это и есть «auto-reset снапшота»;
- **`--network none`** — атакующий не может достучаться наружу (нет exfil/C2);
- лимиты `--memory 128m --cpus 0.5 --pids-limit 64` и `--cap-drop ALL`, без
  монтирований хоста;
- полная **запись сессии** в том данных агента, команды — как события
  `command` уровня `high` + событие `session_recording`.

Безопасность здесь — за счёт жёсткой изоляции, а не эмуляции. Хост ловушки
должен иметь доступ к Docker-сокету и `docker` CLI (образ `agent/Dockerfile.high`),
поэтому High — **только для изолированного стенда**. Включается отдельным
оверлеем `docker-compose.high.yml` (комбинируется с dev или prod); порт fake-SSH
публикуется только на `127.0.0.1` (доступ через SSH-туннель). Профиль и ловушка
создаются сидером только при заданном `SEED_HIGH_ENROLL_TOKEN`.

Точки расширения, заложенные ещё на Must и использованные здесь:

- **Уровень в модели:** `profiles.level` допускает значение `high` уже сейчас; High-interaction — это просто ещё один тип ловушки, а не отдельная подсистема.
- **Обобщённая телеметрия:** модели `sessions` / `events` / `artifacts` не завязаны на эмуляцию. High-interaction репортит те же `session` + `command`-события и складывает запись сессии/pcap в `artifacts` (`kind=session_log|pcap`). Схему БД менять не придётся.
- **Контракт агента нейтрален:** агент не знает, Low это, Medium или High — он транслирует события от локального источника. High-interaction-«сенсор» (например, перехват ввода в VM или `tty`-логгер) публикует события тем же способом, что и ловушки (§7), через общий `honeypots/common/`.
- **Хранилище артефактов:** путь `artifacts.path` и docker-том под записи сессий закладываем в compose заранее (пустой том `artifacts`), чтобы не трогать инфраструктуру позже.
- **Изоляция — отдельный профиль сети:** в `docker-compose` оставляем комментарий-плейсхолдер под будущую сеть `vmnet` (строгая изоляция, лимиты ресурсов, авто-сброс снапшота), чтобы VM не попадала в honeynet напрямую.

Таким образом подключение High-interaction сведётся к: новый контейнер/VM-сенсор + профиль `level=high` + маршрутизация его событий через существующий агентский endpoint. Код центра и БД остаются неизменными.
```
