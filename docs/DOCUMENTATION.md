# HoneyForge — полная документация

Единый документ: от того, что это за приложение, до гайда по использованию.
Отдельные материалы: [DESIGN](DESIGN.md) · [architecture](architecture.md) ·
[db-schema](db-schema.md) · [DEPLOY](DEPLOY.md) · [TEAM](TEAM.md) ·
[presentation](presentation.md).

## Содержание
1. [Что это](#1-что-это)
2. [Какие проблемы решает](#2-какие-проблемы-решает)
3. [Возможности](#3-возможности)
4. [Архитектура](#4-архитектура)
5. [Стек и структура репозитория](#5-стек-и-структура-репозитория)
6. [Быстрый старт](#6-быстрый-старт)
7. [Режимы запуска](#7-режимы-запуска)
8. [Гайд по дашборду](#8-гайд-по-дашборду)
9. [Как «атаковать» (демо-сценарии)](#9-как-атаковать-демо-сценарии)
10. [Ловушки: уровни взаимодействия](#10-ловушки-уровни-взаимодействия)
11. [Профили ловушек](#11-профили-ловушек)
12. [Маскировка канала](#12-маскировка-канала)
13. [API](#13-api)
14. [Схема БД](#14-схема-бд)
15. [Развёртывание на сервере](#15-развёртывание-на-сервере)
16. [Эксплуатация и troubleshooting](#16-эксплуатация-и-troubleshooting)
17. [Безопасность и границы стенда](#17-безопасность-и-границы-стенда)
18. [Карта требований](#18-карта-требований)
19. [Планы развития](#19-планы-развития)

---

## 1. Что это

**HoneyForge** — централизованная платформа управления ловушками (honeypots)
для Blue Team / SOC. Оператор настраивает профили ловушек, разворачивает их на
удалённых хостах, в реальном времени собирает телеметрию атак, хранит и
анализирует её. Ключевая особенность: **ловушка маскирует факт и канал связи с
центром**, чтобы атакующий не распознал её по сетевым признакам.

---

## 2. Какие проблемы решает

### Проблема 1 — парк ловушек не масштабируется, данные разрознены
Классические ловушки разворачиваются и настраиваются поштучно, вручную, а
собранные данные разрознены. При масштабировании до десятков ловушек трудно
поддерживать единые профили, централизованно собирать IoC и быстро реагировать.

| Боль | Решение |
|---|---|
| Поштучная ручная настройка | **Профили** как шаблоны: один профиль → много ловушек |
| Нет единой точки управления | **Control API + dashboard**: статусы, список, регистрация |
| Разрозненные данные | **Централизованный коллектор** → один PostgreSQL, фильтры, сессии |
| Тяжело разворачивать десятки | **Оркестратор**: деплой из профиля одной кнопкой |
| IoC разбросаны | **Экспорт IoC** (CSV/STIX) из единой базы |
| Медленная реакция | **Realtime-лента** + **пороговые алерты** |

### Проблема 2 — продвинутый атакующий «спаливает» ловушку
Попав на хост, нарушитель ищет признаки мониторинга: подозрительные исходящие на
«центр», нетипичные процессы-агенты, характерные артефакты. Если ловушка спалена
— её ценность теряется. **Маскировка у нас — архитектурный принцип:**

| Что ищет нарушитель | Чем закрыто |
|---|---|
| Исходящие на «центр» | Телеметрия по TLS на `/assets/v3/*` под видом CDN (MASK-1/2); джиттер beacon'ов (MASK-5) |
| Нетипичные процессы-агенты | Маскировка имени процесса, без маркеров `honeypot`/`c2` (MASK-4) |
| Путь к мониторингу | Сегментация: из приманки нет маршрута к центру/БД (MASK-3) |
| Баннеры/тайминги | Анти-фингерпринтинг (MASK-6) |
| Перехват канала | mTLS с pinning и ротацией, только на агентских путях (MASK-7) |

---

## 3. Возможности

- **Центр:** Control API (FastAPI), PostgreSQL, Redis, аутентификация оператора + аудит.
- **Ловушки:** Low (баннеры), Medium (fake-SSH/HTTP), High (реальная изолированная песочница).
- **Канал:** TLS + маскировка под CDN + сегментация сетей + (опц.) mTLS.
- **Realtime:** WebSocket-лента, статусы ловушек.
- **Dashboard:** список ловушек, живая лента, фильтры, карточки сессий, алерты, экспорт IoC, деплой из профиля.
- **Bonus:** оркестратор, джиттер, анти-фингерпринтинг, алерты, IoC CSV/STIX, honeytokens, High-interaction, mTLS.

---

## 4. Архитектура

```
             ┌──────────────── mgmt (внутренняя, internal) ────────────────┐
 оператор ─TLS─▶ Nginx ─▶ Control API (FastAPI) ─▶ PostgreSQL              │
   (браузер)       │  dashboard SPA   │   ▲    │                            │
                   └── WebSocket ──────┘   │    └─▶ Redis (pub/sub)          │
             └──────────────────────────────┼─────────────────────────────┘
                                            │ публикация событий
             ┌──────────────── honeynet (сегмент приманки) ────────────────┐
  атакующий ─scan/ssh/http─▶ [Low] [Medium] [High]                          │
             │                     │ события  │                             │
             │                     └─▶ Агент ─TLS(beacon, замаскировано)─▶ Nginx ┘
             └───────────────────────────────────────────────────────────────┘
```

Подробные диаграммы (Mermaid, рендерятся на GitHub) — в [architecture.md](architecture.md).

**Инварианты:**
- `mgmt` — internal-сеть: из `honeynet` нет маршрута к центру и БД. Мост — только Nginx.
- Агент знает только публичный замаскированный URL, не адрес центра/БД.
- Оператор не имеет прямого доступа к БД.

---

## 5. Стек и структура репозитория

**Стек:** Python 3.12 / FastAPI · PostgreSQL 16 · Redis 7 · Nginx · React+Vite+TS · docker-compose.

```
HoneyForge_rep/
├─ docker-compose.yml            # базовый стек (безопасный по умолчанию)
├─ docker-compose.override.yml   # dev-удобства (авто-загрузка)
├─ docker-compose.prod.yml       # прод/demo-режим
├─ docker-compose.high.yml       # High-interaction (опц.)
├─ docker-compose.mtls.yml       # mTLS (опц.)
├─ .env.example
├─ center/                       # Control API + коллектор + realtime
│  ├─ app/ (api, db, schemas, security, services, realtime, alembic)
│  └─ scripts/ (seed.py, gen_certs.py)
├─ agent/                        # агент ловушки (honeyagent)
├─ honeypots/                    # low / medium / high
├─ dashboard/                    # React + Vite
├─ nginx/                        # конфиги + mtls-вариант
├─ scripts/                      # gen-certs.sh, demo-attack.sh
└─ docs/
```

---

## 6. Быстрый старт

Нужен Docker + docker compose v2.

```bash
cp .env.example .env
docker compose up --build
```

Одна команда поднимает весь стек: `cert-init` генерирует TLS-сертификаты, центр
применяет миграции и засевает оператора/профили/ловушки, ловушки
самозапускаются. Проверка:

```bash
curl http://localhost:8080/healthz
# {"status":"ok","checks":{"postgres":"ok","redis":"ok"}}
```

Dashboard: `http://localhost:8080` · логин `admin` · пароль из `.env`
(`SEED_OPERATOR_PASSWORD`, по умолчанию `honeyforge-admin`).

---

## 7. Режимы запуска

| Режим | Команда | Что даёт |
|---|---|---|
| **Dev** (по умолчанию) | `docker compose up -d` | Авто-override: порты ловушек на хосте, оркестратор, hot-reload |
| **Prod / demo** | `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` | Наружу только дашборд; ловушки внутренние; оркестратор выключен |
| **+ High-interaction** | добавить `-f docker-compose.high.yml` | Ловушка с реальной изолированной песочницей (нужен `SEED_HIGH_ENROLL_TOKEN`) |
| **+ mTLS** | добавить `-f docker-compose.mtls.yml` | Взаимный TLS с pinning и ротацией на агентском канале |

Пример (прод + High):
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.high.yml up -d --build
```

Пример (локальный mTLS-демо):
```bash
docker compose -f docker-compose.yml -f docker-compose.override.yml -f docker-compose.mtls.yml up -d --build
```

Seed выполняется автоматически при старте центра (идемпотентно). Вручную:
```bash
docker compose exec -e PYTHONPATH=/app center python scripts/seed.py
```

---

## 8. Гайд по дашборду

Войдите на `http://<host>:<port>` под оператором.

- **Honeypots** (слева) — список ловушек со статусом online/offline/unknown и
  last-seen. Клик по карточке фильтрует ленту по этой ловушке.
- **Top sources** — топ IP-источников атак.
- **Deploy honeypot** — деплой новой ловушки из профиля одной кнопкой (виден
  только если оркестратор доступен; на проде скрыт).
- **Alerts** (сверху ленты) — срабатывания правил (брутфорс, honeytoken).
- **Event feed** — живая лента: `scan`, `connect`, `auth_attempt` (пароль
  замаскирован), `command`, `http_request`, `token_trigger`. Клик по событию
  сессии открывает карточку с кредами (маска) и транскриптом команд.
- **Фильтры** — по ловушке / типу события / IP источника.
- **Export CSV / STIX** (сверху) — выгрузка индикаторов компрометации.
- Индикатор **● live** — активное WebSocket-соединение.

---

## 9. Как «атаковать» (демо-сценарии)

> Порты ловушек не выставлены в интернет. Атака идёт либо скриптом на сервере,
> либо через SSH-туннель к хосту.

### Всё одной командой
```bash
cd <project> && bash scripts/demo-attack.sh
```
Скан Low → брутфорс SSH → успешный вход и чтение honeytoken → попытка входа в
fake-HTTP. Через ~10 c всё в ленте, вверху загораются алерты.

### Руками (локально — порты опубликованы dev-override'ом; на сервере — через туннель)

**Low-ловушка (баннеры):**
```bash
printf 'USER root\r\n' | nc localhost 2021     # FTP; также 2023 (telnet), 23306 (MySQL)
```

**Medium fake-SSH:**
```bash
ssh -p 2222 admin@localhost          # пароль admin123
# внутри:
whoami ; cat /etc/passwd ; cat /root/.aws/credentials ; exit
```
`cat /root/.aws/credentials` — honeytoken, сработает алерт. Пароль в ленте маскируется.

**Medium fake-HTTP админка:**
```
http://localhost:8081/admin   → ввести любые логин/пароль → событие http_request
```

**High-interaction (реальная ОС):**
```bash
ssh -p 2223 root@localhost           # пароль toor
# внутри — настоящий Alpine:
cat /etc/os-release ; id ; echo t > /tmp/x && cat /tmp/x ; exit
```
Команды выполняются по-настоящему в одноразовой изолированной песочнице; после
выхода песочница уничтожается (auto-reset). События — уровня `high`.

### На сервере (порты только на 127.0.0.1) — через SSH-туннель
```bash
ssh -L 2222:127.0.0.1:2222 -L 2223:127.0.0.1:2223 root@<server>
# затем в новом окне ssh -p 2222 admin@localhost  /  ssh -p 2223 root@localhost
```

---

## 10. Ловушки: уровни взаимодействия

| Уровень | Что это | Что ловит | Порты (dev) |
|---|---|---|---|
| **Low** | TCP-баннеры (FTP/telnet/MySQL) | Скан/подключение, источник, порт | 2021, 2023, 23306 |
| **Medium** | fake-SSH + fake-HTTP админка + fake-MySQL | Логины/пароли (маскируются), команды, SQL-запросы, сессии, honeytokens | 2222, 8081, 13306 |
| **High** | fake-SSH + **реальная** одноразовая изолированная песочница | Реальные команды, запись сессии, auto-reset | 2223 |

**High — как сделано безопасно:** одноразовый контейнер на сессию
(`docker run --rm`), `--network none` (нет выхода наружу), лимиты CPU/RAM/PID,
`--cap-drop ALL`, без монтирований хоста; уничтожается при отключении.
Атакующий сидит в песочнице, не в контейнере агента и не на хосте. Lab-only.

---

## 11. Профили ловушек

Профиль — JSON-шаблон конфигурации, применяемый к ловушкам. Пример (Medium):

```json
{
  "name": "Medium — fake SSH + HTTP admin",
  "level": "medium",
  "config": {
    "services": [
      {"type": "ssh", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1",
       "fake_credentials": [{"username": "admin", "password": "admin123"}],
       "fake_fs": "ubuntu-minimal"},
      {"type": "http", "port": 80, "server_header": "nginx/1.24.0", "admin_path": "/admin"}
    ],
    "logging": {"capture_commands": true, "mask_passwords": true},
    "masking": {"beacon_jitter_s": [8, 15], "process_name": "systemd-timesyncd"}
  }
}
```

Типы сервисов: `tcp` (Low-баннер), `ssh`/`http` (Medium), `ssh_high` (High).
Агент получает конфиг от центра при enroll и строит из него ловушки.

---

## 12. Маскировка канала

| Код | Механизм |
|---|---|
| MASK-1 | TLS на канале телеметрии (терминация на Nginx :8443) |
| MASK-2 | Замаскированный endpoint `/assets/v3/*` под видом CDN; рерайт в `/agent/*`; без маркеров |
| MASK-3 | Сегментация: `mgmt` internal, из `honeynet` нет маршрута к центру/БД |
| MASK-4 | Скрытность агента: имя процесса `systemd-timesyncd`, без строк-маркеров |
| MASK-5 | Джиттер beacon'ов из профиля (нет фиксированного периода) |
| MASK-6 | Анти-фингерпринтинг: рандомные задержки баннеров и SSH-аутентификации |
| MASK-7 | mTLS с pinning CA и ротацией клиентского сертификата (только на агентских путях) |

mTLS снимает конфликт с MASK-2 так: `ssl_verify_client optional` — обложка-CDN
работает без сертификата, клиентский сертификат нужен только на `/assets/v3/*`.

---

## 13. API

Два независимых контура. Полные контракты — в [DESIGN §6](DESIGN.md).

**Операторский (mgmt, `/api/v1`, JWT):**
```
POST /auth/login · /auth/refresh · GET /me
GET/POST/PUT/DELETE /profiles[/{id}]
GET/POST/DELETE /honeypots[/{id}] · POST /honeypots/deploy
GET /events?honeypot_id=&type=&source_ip=&from=&to=&limit=&cursor=
GET /sessions/{id} · GET /stats/summary · GET /stats/capabilities
GET /alerts · GET /export/iocs?format=csv|stix
WS  /api/v1/ws?token=<JWT>     # realtime-лента
Swagger: /docs
```

**Агентский (замаскирован Nginx'ом, honeynet):**
```
POST /assets/v3/register   -> /agent/enroll      (bootstrap по enroll-токену)
GET  /assets/v3/manifest.json -> /agent/config
POST /assets/v3/collect    -> /agent/telemetry   (beacon + события)
POST /assets/v3/renew      -> /agent/rotate       (ротация cert при mTLS)
```
Аутентификация агента: опаковый ключ в заголовке `X-Request-Id` (+ mTLS при включении).

---

## 14. Схема БД

Таблицы: `operators`, `profiles`, `honeypots`, `events`, `sessions`,
`auth_attempts`, `artifacts`, `honeytokens`, `alerts`, `audit_log`. Миграции —
Alembic (применяются на старте центра). ER-диаграмма — в [db-schema.md](db-schema.md),
описание полей — в [DESIGN §5](DESIGN.md).

Ключевое: пароли в `auth_attempts` — только хэш + маска (не в открытом виде);
`events.dedup_key` обеспечивает идемпотентность дослылки из буфера агента.

---

## 15. Развёртывание на сервере

Demo-режим (наружу только дашборд, ловушки внутренние). Коротко:

```bash
sudo mkdir -p /opt/honeyforge && cd /opt/honeyforge
git clone <repo> .
cp .env.example .env
# сгенерировать сильные секреты:
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 24)|" .env
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$(openssl rand -hex 32)|" .env
sed -i "s|^SEED_OPERATOR_PASSWORD=.*|SEED_OPERATOR_PASSWORD=$(openssl rand -hex 18)|" .env
# слушать только localhost (за reverse-proxy) или нужный порт:
sed -i "s|^MGMT_HTTP_PORT=.*|MGMT_HTTP_PORT=127.0.0.1:9080|" .env
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Доступ команды: за reverse-proxy с TLS, через Cloudflare-туннель, или открыть
порт только доверенным IP через фаервол. Детали — в [DEPLOY.md](DEPLOY.md).

Включить High на сервере: добавить `SEED_HIGH_ENROLL_TOKEN` в `.env`,
`docker pull alpine:3.20`, и поднять с `-f docker-compose.high.yml`.

**Текущий стенд проекта:** `http://93.88.204.70:9080` (demo-режим, Low+Medium+High;
High доступен через SSH-туннель на порт 2223).

---

## 16. Эксплуатация и troubleshooting

```bash
# статус / логи
docker compose [-f ...] ps
docker compose [-f ...] logs -f center
docker compose [-f ...] logs honeypot-medium | grep enrolled

# обновление
git pull && docker compose [-f ...] up -d --build

# остановка (данные сохраняются) / полное удаление
docker compose [-f ...] down
docker compose [-f ...] down -v
```

**Частые ситуации:**
- *Ловушка offline* — агент не смог зарегистрироваться: проверьте, что seed создал
  ловушку (совпадение enroll-токена) и Nginx поднят; агент сам ретраит enroll.
- *Порт занят* — смените `MGMT_HTTP_PORT` в `.env`.
- *Нет событий* — события приходят по beacon-интервалу (~10 c); проверьте логи агента.
- *mTLS: 403 на агентских путях* — у агента нет клиентского сертификата (должен
  появиться после enroll); проверьте, что `cert-init` сгенерировал CA (`ca.crt`).

---

## 17. Безопасность и границы стенда

- Только изолированная лабораторная сеть/DMZ; всё синтетическое.
- «Маскировка» — имитация легитимного трафика для атакующего **внутри стенда**,
  не для сокрытия от владельца инфраструктуры или контролирующих органов.
- Разворачивание — с письменного согласия владельца стенда.
- Секреты не в коде: `.env`/secret-store; дефолтные пароли меняются для прода.
- High-interaction — только на изолированном стенде (реальное выполнение команд).

---

## 18. Карта требований

| Код | Требование | Приоритет | Статус |
|---|---|---|---|
| FR-C1 | CRUD профилей | Must | ✅ |
| FR-C2 | Регистрация ловушек, статусы | Must | ✅ |
| FR-C3 | Конфиг + приём телеметрии (защищённый endpoint) | Must | ✅ |
| FR-C4 | Хранение событий + фильтрация | Must | ✅ |
| FR-C5 | Аутентификация оператора | Must | ✅ |
| FR-C6 | Оркестратор деплоя | Bonus | ✅ |
| FR-C7 | Алерты + IoC-экспорт (CSV/STIX) | Bonus | ✅ |
| FR-A1 | Два уровня (Low, Medium) | Must | ✅ (+ High) |
| FR-A2 | Логирование активности | Must | ✅ |
| FR-A3 | Телеметрия + приём конфига | Must | ✅ |
| FR-A4 | Буферизация + дослылка | Must | ✅ |
| FR-A5 | High-interaction с записью сессии | Bonus | ✅ |
| FR-A6 | Honeytokens + фиксация | Bonus | ✅ |
| MASK-1 | TLS | Must | ✅ |
| MASK-2 | Неприметный endpoint | Must | ✅ |
| MASK-3 | Сегментация сетей | Must | ✅ |
| MASK-4 | Скрытность агента | Must | ✅ |
| MASK-5 | Джиттер beacon'ов | Bonus | ✅ |
| MASK-6 | Анти-фингерпринтинг | Bonus | ✅ |
| MASK-7 | mTLS с pinning и ротацией | Bonus | ✅ |

Закрыт весь Must и весь Bonus.

---

## Продвинутые возможности (сверх ТЗ)

Три фичи, выделяющие платформу на фоне типовых honeypot-решений:

- **Корреляция атакующих + MITRE ATT&CK (#2).** Каждое событие/команда авто-
  размечается по ATT&CK; центр агрегирует одного атакующего **через весь парк**
  (сколько ловушек затронул, какие техники, threat-score). API: `GET /attackers`,
  `GET /attackers/{ip}`; в UI — панель «Attackers» и модалка с разбивкой по ATT&CK,
  плюс тег техники на каждом событии ленты.
- **Адаптивная лестница обмана (#3).** При high-алерте (брутфорс/honeytoken)
  платформа **авто-разворачивает decoy-ловушку** из профиля через оркестратор —
  с лимитом (`DECEPTION_MAX_DECOYS`) и дедупом по источнику. API: `GET /deception`;
  в UI — панель «Deception» и бейдж `auto` на авто-ловушках.
- **Само-детекция «ловушку спалили?» (#4).** Детектор recon-за-мониторингом
  (`ps`, `netstat`, `systemd-detect-virt`, поиск `honeypot`/`cowrie`, чтение
  `.bash_history`) поднимает алерт `honeypot_probe` и **авто-ре-маскирует** ловушку
  (ротация имени процесса через конфиг; агент переприменяет его на лету). В UI —
  бейдж `⚠ exposed` на карточке ловушки.

Настройки — в `center/app/config.py` (`deception_*`, `selfdefense_*`).

## 19. Планы развития

- Графики аналитики (Chart.js): события по времени, карта/топ источников.
- Автотесты (pytest) + CI (GitHub Actions).
- Уведомления об алертах (Telegram/webhook).
- Загрузка артефактов (записи High-сессий, pcap) в центр и просмотр в UI.
- Обогащение IP (GeoIP/ASN); ещё типы ловушек (SMB/RDP/Redis).
- High-interaction на полноценных VM (не только контейнеры).
- HTTPS для дашборда (именованный туннель/домен) и защита логина от брутфорса.
