package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-proxy-guard/internal/auth"
	"go-proxy-guard/internal/config"
	"go-proxy-guard/internal/keys"
	"go-proxy-guard/internal/logger"
	"go-proxy-guard/internal/proxy"
	"go-proxy-guard/internal/redis"
)

var version = "dev"

func main() {
	// Определяем пути к конфигурационным файлам
	appConfigPath := getEnvOrDefault("APP_CONFIG", "configs/app.json")
	proxyConfigPath := getEnvOrDefault("PROXY_CONFIG", "configs/proxy.json")

	// Загружаем конфигурацию
	cfg, err := config.LoadConfig(appConfigPath, proxyConfigPath)
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	// Инициализируем логгер
	appLogger, err := logger.New(cfg.App.Logging)
	if err != nil {
		log.Fatalf("Ошибка инициализации логгера: %v", err)
	}
	defer func() {
		if closer, ok := appLogger.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()

	appLogger.Info("Запуск go-proxy-guard", logger.NewField("version", version))

	// Получаем путь к директории ключей из конфигурации или переменной окружения
	keysDir := getEnvOrDefault("KEYS_DIR", cfg.App.Keys.Dir)

	// Создаем хранилище ключей
	keyStore, err := keys.NewFileStore(keysDir)
	if err != nil {
		appLogger.Error("Ошибка создания хранилища ключей", logger.NewField("error", err.Error()))
		log.Fatalf("Ошибка создания хранилища ключей: %v", err)
	}

	// Инициализируем ключи для всех поддерживаемых алгоритмов
	if err := keyStore.InitializeKeys(cfg.App.Token.AlgSupported); err != nil {
		appLogger.Error("Ошибка инициализации ключей", logger.NewField("error", err.Error()))
		log.Fatalf("Ошибка инициализации ключей: %v", err)
	}

	appLogger.Info("Ключи инициализированы")

	// Создаем клиент Redis
	redisClient, err := redis.NewClient(cfg.App.Redis)
	if err != nil {
		appLogger.Error("Ошибка подключения к Redis", logger.NewField("error", err.Error()))
		log.Fatalf("Ошибка подключения к Redis: %v", err)
	}
	defer redisClient.Close()

	appLogger.Info("Подключение к Redis установлено")

	// Создаем сервисы
	authService := auth.NewService(cfg.App, keyStore, redisClient)
	proxyService := proxy.NewService(cfg.App, cfg.Proxy, keyStore)

	// Создаем HTTP сервер
	server := &http.Server{
		Addr:         getEnvOrDefault("LISTEN_ADDR", ":8080"),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Настраиваем маршрутизацию
	mux := http.NewServeMux()

	// Эндпоинты для работы с токенами
	mux.HandleFunc("/api/v1/tokens/generate", handleGenerateTokens(authService, appLogger))
	mux.HandleFunc("/api/v1/tokens/refresh", handleRefreshTokens(authService, appLogger))

	// Все остальные запросы идут в proxy
	mux.HandleFunc("/", handleProxy(proxyService, appLogger, cfg.App))

	// Обертываем в middleware для логирования
	handler := loggingMiddleware(mux, appLogger)

	server.Handler = handler

	// Запускаем сервер в отдельной горутине
	go func() {
		appLogger.Info("HTTP сервер запущен", logger.NewField("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("Ошибка HTTP сервера", logger.NewField("error", err.Error()))
			log.Fatalf("Ошибка HTTP сервера: %v", err)
		}
	}()

	// Ожидаем сигнал для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Получен сигнал завершения, начинаем graceful shutdown")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		appLogger.Error("Ошибка при shutdown сервера", logger.NewField("error", err.Error()))
		log.Fatalf("Ошибка при shutdown сервера: %v", err)
	}

	appLogger.Info("Сервер остановлен")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
