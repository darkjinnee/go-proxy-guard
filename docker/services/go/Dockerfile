# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Копируем go.mod и go.sum
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-w -s" -o proxy-guard ./cmd/proxy-guard

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata wget

WORKDIR /app

# Копируем бинарник из builder
COPY --from=builder /build/proxy-guard .

# Копируем конфигурационные файлы
COPY --from=builder /build/configs ./configs

# Создаем директории для ключей и логов
RUN mkdir -p /var/lib/go-proxy-guard/keys /var/log/go-proxy-guard

# Устанавливаем права доступа
RUN chmod 755 proxy-guard && \
    chmod 700 /var/lib/go-proxy-guard/keys && \
    chmod 755 /var/log/go-proxy-guard

# Пользователь для запуска (не root)
RUN addgroup -g 1000 proxy && \
    adduser -D -u 1000 -G proxy proxy && \
    chown -R proxy:proxy /app /var/lib/go-proxy-guard /var/log/go-proxy-guard

USER proxy

EXPOSE 8080

# Переменные окружения по умолчанию
ENV LISTEN_ADDR=:8080
ENV APP_CONFIG=/app/configs/app.json
ENV PROXY_CONFIG=/app/configs/proxy.json
ENV KEYS_DIR=/var/lib/go-proxy-guard/keys

CMD ["./proxy-guard"]
