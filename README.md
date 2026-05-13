# go-proxy-guard

REST API сервис для аутентификации и авторизации на основе JWT токенов с последующим проксированием запросов.

## Описание

`go-proxy-guard` — это reverse proxy с встроенной системой аутентификации на основе JWT (JSON Web Tokens). Сервис выполняет валидацию JWT токенов и проксирование авторизованных запросов к внутренним сервисам согласно конфигурации маршрутизации.

## Основные возможности

- Генерация пары JWT токенов (access_token и refresh_token) с поддержкой различных алгоритмов подписи (HS256, RS256, RS512, ES256, EdDSA)
- Обновление токенов на основе валидного refresh_token
- Защита от повторного использования refresh токенов через Redis
- Валидация JWT токенов перед проксированием запросов
- HTTP reverse proxy с маршрутизацией по доменам и путям
- Управление криптографическими ключами с шифрованием
- Структурированное логирование с ротацией

## Структура проекта

Проект следует стандарту [golang-standards/project-layout](https://github.com/golang-standards/project-layout):

```
go-proxy-guard/
├── cmd/proxy-guard/     # Точка входа приложения
├── internal/           # Внутренний код приложения
│   ├── auth/          # Логика аутентификации
│   ├── proxy/         # Логика проксирования
│   ├── config/        # Загрузка конфигурации
│   ├── keys/          # Управление ключами
│   ├── redis/         # Работа с Redis
│   └── logger/        # Логирование
├── pkg/jwt/           # Утилиты для работы с JWT
├── configs/           # Файлы конфигурации
├── docker/            # Docker конфигурации
└── docs/              # Документация
```

## Быстрый старт

### Требования

- Go 1.21 или выше (для локальной разработки)
- Docker и docker-compose (для запуска через Docker)
- Redis (для хранения использованных refresh токенов)

### Локальная разработка

#### Установка зависимостей

```bash
go mod download
```

#### Сборка

```bash
make build
```

Бинарник будет создан в `bin/proxy-guard`.

#### Конфигурация

1. Настройте `configs/app.json` — глобальные настройки приложения
2. Настройте `configs/proxy.json` — конфигурация маршрутизации
3. (Опционально) Создайте `.env` файл для переопределения настроек из `app.json`

Все настройки из `configs/app.json` можно переопределить через переменные окружения или `.env` файл. Если переменная не задана, используется значение из конфигурации.

Пример `.env` файла (см. `.env.example`):
```bash
REDIS_HOST=localhost
REDIS_PORT=6379
KEYS_DIR=./keys
LOGGING_LEVEL=debug
MASTER_KEY=your-master-key-here
```

#### Запуск

```bash
# Через make
make run

# Или напрямую
./bin/proxy-guard

# С переменными окружения
LISTEN_ADDR=:8080 \
APP_CONFIG=configs/app.json \
PROXY_CONFIG=configs/proxy.json \
KEYS_DIR=./keys \
./bin/proxy-guard
```

### Запуск через Docker

#### Быстрый старт

```bash
# Сборка и запуск всех сервисов
docker compose -f compose.yml up -d --build
```

#### Переменные окружения

Важные переменные окружения для Docker:

- `MASTER_KEY` — мастер-ключ для шифрования ключей (ОБЯЗАТЕЛЬНО в продакшене!)
- `LISTEN_ADDR` — адрес для прослушивания (по умолчанию `:8080`)
- `HTTP_PORT` — порт в URL [healthcheck](https://docs.docker.com/reference/compose-file/services/#healthcheck) в `compose.yml` (по умолчанию `8080`). Подставляется при `docker compose` из `.env` или окружения shell; должен совпадать с портом в `LISTEN_ADDR` (например `:8080` → `8080`), иначе контейнер будет помечаться как unhealthy.
- `APP_CONFIG` — путь к файлу app.json (по умолчанию `/app/configs/app.json`)
- `PROXY_CONFIG` — путь к файлу proxy.json (по умолчанию `/app/configs/proxy.json`)
- `KEYS_DIR` — директория для хранения ключей (по умолчанию `/var/lib/go-proxy-guard/keys`)

#### Просмотр логов

```bash
docker compose logs -f proxy
```

#### Остановка

```bash
docker compose down
```

## Конфигурация

### app.json

Глобальные настройки приложения:

- `proxy` — настройки проксирования (таймауты, размер тела запроса)
- `token` — настройки JWT токенов (время жизни, алгоритмы, IP whitelist)
- `redis` — настройки подключения к Redis
- `logging` — настройки логирования (уровень, формат, ротация)

### proxy.json

Файл — **JSON-массив** объектов (по одному на каждый обслуживаемый домен). Порядок элементов не важен; после загрузки домены индексируются по имени.

У каждого элемента:

- `domain` (обязательно) — значение HTTP-заголовка `Host` без учёта регистра; порт, если указан в запросе, при сопоставлении отбрасывается
- `label` (опционально) — проверка соответствия `kid` в заголовке JWT токена
- `routes` (обязательно) — список правил маршрутизации (путь, метод, IP-фильтры, куда проксировать и т.д.)

Дубликаты одного и того же домена (после нормализации) в файле недопустимы — конфигурация не загрузится.

Пример структуры:

```json
[
  {
    "domain": "api.example.com",
    "label": "api-key-label",
    "routes": [
      {
        "match": { "path": "/v1/users/*", "method": ["GET", "POST"] },
        "forward_to": { "url": "http://users-service.internal:8080" }
      }
    ]
  }
]
```

Полный пример с несколькими доменами см. в [configs/proxy.json](configs/proxy.json).

## API эндпоинты

### Проверка работоспособности (liveness)

```bash
GET /health
# или
HEAD /health
```

Ответ **`200 OK`** без тела. Не зависит от Redis и подходит для проверок вроде `wget --spider` (GET/HEAD), в отличие от `/api/v1/tokens/generate`, который принимает только **POST**.

В Docker (`compose.yml`) healthcheck сервиса `proxy` обращается к `http://localhost:${HTTP_PORT:-8080}/health`.

### Генерация токенов

```bash
POST /api/v1/tokens/generate
Content-Type: application/json

{
  "header": {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "custom-key-id-123"
  },
  "payload": {
    "user_id": "12345",
    "username": "johndoe",
    "role": "admin"
  }
}
```

**Параметры запроса**:
- `header.alg` (required): Алгоритм подписи токена (HS256, RS256, RS512, ES256, EdDSA)
- `header.typ` (required): Тип токена (JWT)
- `header.kid` (optional): Key ID для идентификации ключа в заголовке токена. Если не указан, используется ID ключа из хранилища
- `payload.*` (required): Claims токена (данные пользователя)

**Ответ:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Обновление токенов

```bash
POST /api/v1/tokens/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Ответ:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Проксирование запросов

Любой HTTP запрос к доменам, указанным в `proxy.json`, требует валидный access_token:

```bash
GET /v1/users/123
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Claims из токена автоматически добавляются в заголовки `X-JWT-*`.

## Разработка

### Запуск тестов

```bash
make test
```

### Проверка кода

```bash
make lint
make vet
make fmt
```

### Покрытие тестами

```bash
make test-coverage
```

## Безопасность

- **Мастер-ключ**: Обязательно установите `MASTER_KEY` в продакшене через переменную окружения
- **Ключи**: Хранятся в зашифрованном виде с использованием AES-256-GCM
- **Права доступа**: Файлы ключей создаются с правами 0600
- **Логирование**: Токены и ключи никогда не логируются в открытом виде

## Документация

Подробное техническое задание находится в [docs/TZ.md](docs/TZ.md).

## Лицензия

См. файл [LICENSE](LICENSE).
