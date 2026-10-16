# Развёртывание HoneyForge на сервере (demo-режим)

> Demo-режим: наружу доступен только **дашборд оператора**; ловушки слушают
> только во внутренней docker-сети `honeynet` и в интернет не выставляются.
> Оркестратор (монтирование Docker-сокета) выключен. Это безопасно для сервера,
> где есть другие проекты.
>
> ⚠️ Полноценный «боевой» honeypot (ловушки смотрят в интернет) разворачивают
> только на отдельной изолированной VM — см. README.

## Предпосылки

- Docker + docker compose на сервере.
- Отдельный каталог под проект (напр. `/opt/honeyforge`), не пересекается с другими.

## Шаги

```bash
# 1. Клонировать в отдельный каталог
sudo mkdir -p /opt/honeyforge && cd /opt/honeyforge
git clone https://github.com/Try-To-Stay/HoneyForge_rep.git .

# 2. Создать прод-.env с СИЛЬНЫМИ секретами (не дефолтными!)
cp .env.example .env
# сгенерировать и подставить случайные значения:
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/^SEED_OPERATOR_PASSWORD=.*/SEED_OPERATOR_PASSWORD=$(openssl rand -base64 18)/" .env
sed -i "s/^SEED_LOW_ENROLL_TOKEN=.*/SEED_LOW_ENROLL_TOKEN=$(openssl rand -hex 24)/" .env
sed -i "s/^SEED_MEDIUM_ENROLL_TOKEN=.*/SEED_MEDIUM_ENROLL_TOKEN=$(openssl rand -hex 24)/" .env
# запомнить пароль оператора:
grep SEED_OPERATOR_PASSWORD .env
# закрыть .env от чтения другими пользователями сервера (там секреты):
chmod 600 .env

# 3. Поднять в demo-режиме (prod overlay, БЕЗ dev-override)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Дашборд: `http://<server>:8080` (порт задаётся `MGMT_HTTP_PORT` в `.env`).
Логин — `admin` и пароль из `SEED_OPERATOR_PASSWORD`.

## Доступ команды и TLS

Дашборд ходит по HTTP. Для доступа команды выберите одно:

- **Рекомендуется:** спрятать за вашим reverse-proxy (nginx/Caddy/Traefik) с TLS
  и своим доменом. Пробросьте `127.0.0.1:8080` → `https://honeyforge.ваш-домен`.
  Для этого поставьте `MGMT_HTTP_PORT=127.0.0.1:8080` в `.env` (слушать только локально).
- **Минимум:** откройте порт `8080` только для доверенных IP команды через фаервол
  (`ufw allow from <team-ip> to any port 8080`). Дашборд защищён логином оператора.

Не открывайте `8080` всему интернету по HTTP без прокси — учётные данные пойдут
в открытом виде.

## Обновление

```bash
cd /opt/honeyforge && git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

## Остановка / удаление

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml down        # остановить
docker compose -f docker-compose.yml -f docker-compose.prod.yml down -v      # + удалить данные
```

Проект изолирован в своём compose-проекте и docker-сетях (`honeyforge_rep_*`),
другие контейнеры на сервере не затрагиваются.
