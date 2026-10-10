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
- Агент, ловушки, realtime и dashboard — следующие спринты (см. DESIGN §9).

## Стек

Python 3.12 / FastAPI · PostgreSQL 16 · Redis 7 · Nginx · React+Vite (dashboard) ·
docker-compose.

## Быстрый старт (Спринт 0)

```bash
cp .env.example .env        # при необходимости отредактируйте секреты
docker compose up --build
```

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
