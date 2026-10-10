# HoneyForge

Централизованная платформа управления ловушками (honeypots) для Blue Team / SOC:
оператор настраивает профили ловушек, разворачивает их на удалённых хостах, в
реальном времени собирает телеметрию атак, хранит и анализирует её. Ловушка
маскирует факт и канал связи с центром, чтобы атакующий не распознал её по
сетевым признакам.

> **Границы стенда.** Только изолированная лабораторная сеть/DMZ. Всё
> синтетическое. «Маскировка» — имитация легитимного трафика для атакующего
> *внутри стенда*, не для сокрытия от владельца инфраструктуры или
> администраторов. Разворачивать — только с письменного согласия владельца стенда.

## Документация

- [docs/DESIGN.md](docs/DESIGN.md) — технический дизайн: стек, архитектура, схема БД, API-контракты.
- [plan for this shit](<plan for this shit>) — исходный план спринтов и карта требований.

## Статус

- **Спринт 0 (каркас)** — готово: `docker compose up` поднимает центр + PostgreSQL + Redis + Nginx, healthcheck зелёный.
- **Спринт 1 (центр-ядро)** — готово: Alembic-миграции (авто при старте), JWT-аутентификация оператора, CRUD профилей (FR-C1), регистрация ловушек со статусами (FR-C2), Swagger, seed-скрипт.
- **Спринт 2 (агент + канал)** — готово: агент (enroll/config-pull/beacon) с устойчивым буфером и дослылкой (FR-A3/FR-A4), Low-ловушка с TCP-баннерами (FR-A1), приём телеметрии и выдача конфига (FR-C3), хранение событий с фильтрами (FR-C4). Канал по TLS (MASK-1) через замаскированный endpoint `/assets/v3/*` (MASK-2); сегментация сетей mgmt/honeynet (MASK-3).
- **Спринт 3 (dashboard + realtime)** — готово: React+Vite dashboard (логин оператора, список ловушек со статусами, живая лента событий по WebSocket, фильтры, top-источники), realtime-слой на WebSocket с подпиской на Redis.
- **Спринт 4 (Medium-ловушка)** — готово: fake-SSH на asyncssh (перехват кредов, интерактивный fake-shell по синтетической ФС, журнал команд) и fake-HTTP админка; материализация сессий и попыток входа на центре с маскированием паролей (FR-A1/FR-A2); деталь сессии в API и UI; скрытность имени процесса агента (MASK-4).

**Все Must-требования закрыты (граница зачёта — конец Спринта 4).** Дальше —
Bonus: оркестратор, алерты, IoC-экспорт, джиттер/анти-фингерпринтинг, mTLS,
High-interaction (см. DESIGN §9).

Dashboard: открыть `http://localhost:8080`, войти оператором. Лента обновляется
в реальном времени; клик по событию сессии открывает детали (креды + команды).
Порты-приманки Medium: `2222`→22 (fake-SSH, `admin`/`admin123`), `8081`→80 (fake-HTTP admin).

## Стек

Python 3.12 / FastAPI · PostgreSQL 16 · Redis 7 · Nginx · React+Vite (dashboard) ·
docker-compose.

## Быстрый старт (Спринт 0)

```bash
cp .env.example .env              # при необходимости отредактируйте секреты
bash scripts/gen-certs.sh         # self-signed TLS для канала телеметрии (один раз)
docker compose up --build
docker compose exec -e PYTHONPATH=/app center python scripts/seed.py   # оператор, профили, Low-ловушка
```

После этого контейнер `honeypot-low` сам регистрируется в центре и начинает
слушать порты-приманки. Проверить сценарий «атака → событие»:

```bash
# «атакующий» подключается к Low-ловушке (host 2021 -> honeypot tcp/21)
printf 'USER root\r\n' | nc localhost 2021
```

Событие появится в `GET /api/v1/events` в течение beacon-интервала (~10 c).
Порты-приманки на хосте: `2021`→21 (FTP), `2023`→23 (telnet), `23306`→3306 (MySQL).

Проверка готовности:

```bash
curl http://localhost:8080/healthz
# {"status":"ok","checks":{"postgres":"ok","redis":"ok"}}
```

- `http://localhost:8080` — операторский контур (Control API; Swagger — `/docs`).
- `http://localhost:8088` — замаскированный публичный контур (приём телеметрии, вводится в Спринте 2).

Засеять демо-оператора и профили (идемпотентно):

```bash
docker compose exec -e PYTHONPATH=/app center python scripts/seed.py
```

Логин оператора (по умолчанию `admin` / значение `SEED_OPERATOR_PASSWORD` из `.env`):

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -d "username=admin&password=honeyforge-admin"
```

Миграции применяются автоматически при старте контейнера `center`
(`alembic upgrade head` в entrypoint).

Остановить: `docker compose down` (данные БД сохраняются в томе `pgdata`;
`docker compose down -v` удалит и данные).

## Структура

См. раздел «Структура репозитория» в [docs/DESIGN.md](docs/DESIGN.md#2-структура-репозитория).

## Разработка

```bash
cd center
pip install -e ".[dev]"
uvicorn app.main:app --reload   # нужны запущенные postgres и redis
```
