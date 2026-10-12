# HoneyForge — архитектура

## Компоненты и потоки

```mermaid
flowchart LR
  attacker([Атакующий]):::att
  operator([Оператор / SOC]):::op

  subgraph honeynet["honeynet — сегмент приманки"]
    direction TB
    low["Low honeypot<br/>TCP-баннеры"]:::hp
    med["Medium honeypot<br/>fake-SSH / fake-HTTP"]:::hp
    high["High honeypot<br/>реальная песочница*"]:::hp
    agent["Агент<br/>beacon · буфер · конфиг"]:::agent
  end

  nginx["Nginx<br/>TLS-терминация<br/>маскировка /assets/v3/*"]:::edge

  subgraph mgmt["mgmt — внутренняя сеть (internal)"]
    direction TB
    center["Control API<br/>(FastAPI)"]:::core
    redis[("Redis<br/>pub/sub")]:::infra
    pg[("PostgreSQL")]:::infra
    dash["Dashboard<br/>(React)"]:::core
  end

  attacker -->|scan / ssh / http| low
  attacker --> med
  attacker --> high
  low -->|события| agent
  med --> agent
  high --> agent
  agent -->|"TLS beacon (замаскировано под CDN)"| nginx
  nginx -->|/agent/*| center

  center --> pg
  center -->|публикует события| redis
  redis -->|поток| center
  operator -->|HTTPS| nginx
  nginx -->|"/api · WebSocket"| center
  nginx -->|SPA| dash

  classDef att fill:#5a1d1d,stroke:#f85149,color:#fff
  classDef op fill:#1d3a5a,stroke:#58a6ff,color:#fff
  classDef hp fill:#2a2118,stroke:#f0b429,color:#eee
  classDef agent fill:#232a18,stroke:#3fb950,color:#eee
  classDef edge fill:#20262e,stroke:#8b97a7,color:#eee
  classDef core fill:#161b22,stroke:#58a6ff,color:#eee
  classDef infra fill:#161b22,stroke:#8b97a7,color:#eee
```

\* High honeypot — lab-only: реальные команды в одноразовой изолированной песочнице.

## Ключевые инварианты

- **MASK-1.** Телеметрия идёт только по TLS (терминация на Nginx :8443).
- **MASK-2.** Снаружи канал выглядит как обычный веб-ресурс: `/assets/v3/collect`,
  `/assets/v3/manifest.json`, `/assets/v3/register` — Nginx переписывает их во
  внутренние `/agent/*`. Никаких строк `honeypot`/`c2`.
- **MASK-3.** `mgmt` — internal-сеть: из `honeynet` **нет маршрута** к центру и БД.
  Мост — только Nginx, и только через замаскированный endpoint.
- **MASK-4.** Агент маскирует имя процесса (напр. `systemd-timesyncd`).
- Оператор не имеет прямого доступа к БД; агент не знает адреса центра/БД —
  только публичный замаскированный URL.

## Сценарий «атака → событие» (последовательность)

```mermaid
sequenceDiagram
  participant A as Атакующий
  participant HP as Ловушка
  participant AG as Агент
  participant NG as Nginx (TLS)
  participant C as Центр
  participant R as Redis
  participant D as Dashboard

  A->>HP: подключение / вход / команда
  HP->>AG: событие (localhost)
  AG->>AG: запись в буфер (SQLite)
  AG->>NG: POST /assets/v3/collect (TLS, beacon)
  NG->>C: /agent/telemetry
  C->>C: нормализация, запись, правила алертов
  C->>R: публикация события/алерта
  R-->>C: подписка (WebSocket)
  C-->>D: push в ленту
  Note over AG,C: при потере связи события копятся в буфере<br/>и досылаются (идемпотентно по dedup_key)
```
