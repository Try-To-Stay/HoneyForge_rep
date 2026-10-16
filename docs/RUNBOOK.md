# HoneyForge — Runbook (управление стендом)

Оперативная шпаргалка: как выставить ловушки в сеть, убрать обратно, запустить
имитацию атаки, смотреть статус и логи. Все команды — **на сервере стенда**,
из каталога проекта.

> `<server>` — адрес стенда (IP или домен), у администратора команды.
> Все режимы комбинируются поверх базового набора; High включён везде.

```bash
ssh root@<server>
cd /opt/honeyforge
```

Удобно задать набор compose-файлов один раз в сессии:

```bash
# базовый demo + High
BASE="-f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.high.yml"
```

---

## 1. Выставить ловушки в сеть (для атаки извне)

```bash
docker compose $BASE -f docker-compose.exposed.yml up -d
```

Публичные порты (на `0.0.0.0`):

| Порт | Ловушка |
|---|---|
| `21` | Low — FTP-баннер |
| `23` | Low — telnet-баннер |
| `2222` | Medium — fake-SSH (`admin`/`admin123`) |
| `8888` | Medium — fake-HTTP админка |
| `3306` | Medium — fake-MySQL |
| `2223` | High — реальная изолированная песочница (`root`/`toor`) |

Проверить, что порты публичные:

```bash
ss -tln | grep -E '0\.0\.0\.0:(21|23|2222|8888|3306|2223) '
```

Если на сервере включён фаервол (ufw) — открыть порты:

```bash
ufw allow 21,23,2222,8888,3306,2223/tcp
```

> ⚠️ Выставленный стенд приглашает реальных сканеров/ботов. Только изолированный
> стенд, по согласованию. Закончили — сразу уберите (п.2).

---

## 2. Убрать из сети (стоп сканерам, вернуть на localhost)

```bash
docker compose $BASE -f docker-compose.local.yml up -d --remove-orphans
```

Локальные порты (только `127.0.0.1`): Low `2021`/`2023`/`23306`,
Medium `2222`(SSH)/`18081`(HTTP)/`13306`(MySQL), High `2223`.

Если открывали фаервол — закрыть:

```bash
ufw delete allow 21,23,2222,8888,3306,2223/tcp
```

Проверить, что публичных ловушек не осталось (наружу — только дашборд `9080`):

```bash
ss -tln | grep -E '0\.0\.0\.0:(21|23|2222|8888|3306|2223) ' && echo "ЕСТЬ публичная!" || echo "OK: ловушки локальные"
```

---

## 3. Имитация атаки — одной командой (с сервера)

Работает в любом режиме (атака идёт изнутри honeynet, порты наружу не нужны):

```bash
bash scripts/demo-attack.sh
```

Сценарий: скан Low (21/23/3306) → брутфорс fake-SSH → вход `admin`/`admin123` →
чтение honeytoken (`/root/.aws/credentials`) → попытка входа в fake-HTTP.
Через ~10 c всё появится в ленте дашборда, сверху загорятся алерты
(brute_force + honeytoken).

---

## 4. Имитация атаки — руками

**Если ловушки ВЫСТАВЛЕНЫ (п.1)** — с любой машины, по `<server>`:

```bash
printf 'USER root\r\n' | nc <server> 21        # Low FTP (также 23, 3306)
ssh -p 2222 admin@<server>                      # Medium fake-SSH, пароль admin123
curl http://<server>:8888/admin -d "username=admin&password=123"   # Medium fake-HTTP
ssh -p 2223 root@<server>                       # High, реальная песочница, пароль toor
```

**Если DROPPED (п.2)** — через SSH-туннель к локальным портам:

```bash
ssh -L 2222:127.0.0.1:2222 -L 2223:127.0.0.1:2223 -L 18081:127.0.0.1:18081 root@<server>
# в новом окне:
ssh -p 2222 admin@localhost        # Medium, admin123
ssh -p 2223 root@localhost         # High, toor
curl http://localhost:18081/admin -d "username=admin&password=123"
```

Внутри fake-SSH для срабатывания honeytoken:

```bash
whoami ; cat /etc/passwd ; cat /root/.aws/credentials ; exit
```

---

## 5. Статус, логи, обслуживание

```bash
docker compose $BASE ps                              # статус контейнеров
curl -s http://127.0.0.1:9080/healthz                # здоровье центра
docker compose $BASE logs -f center                  # логи центра
docker compose $BASE logs honeypot-medium | grep -i command   # команды атакующих
docker compose $BASE logs honeypot-low | grep assets/v3       # замаскированный канал
```

Дашборд: `http://<server>:9080` — логин `admin`, пароль из `SEED_OPERATOR_PASSWORD`
в `/opt/honeyforge/.env`.

Обновить код и пересобрать:

```bash
git pull && docker compose $BASE -f docker-compose.local.yml up -d --build
```

Остановить / удалить данные:

```bash
docker compose $BASE down            # остановить (БД в томе pgdata сохраняется)
docker compose $BASE down -v         # + удалить данные
```
