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

	// Загружаем конфигурацию с поддержкой .env
	appCfg, err := config.LoadAppConfigWithEnv(appConfigPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	proxyCfg, err := config.LoadProxyConfig(proxyConfigPath)
	if err != nil {
		log.Fatalf("Error loading proxy config: %v", err)
	}

	cfg := &config.Config{
		App:   appCfg,
		Proxy: proxyCfg,
	}

	// Инициализируем логгер
	appLogger, err := logger.New(cfg.App.Logging)
	if err != nil {
		log.Fatalf("Error initializing logger: %v", err)
	}
	defer func() {
		if closer, ok := appLogger.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()

	appLogger.Info("Starting go-proxy-guard", logger.NewField("version", version))

	// Получаем путь к директории ключей из конфигурации (уже переопределен из .env если нужно)
	keysDir := cfg.App.Keys.Dir

	// Создаем хранилище ключей
	keyStore, err := keys.NewFileStore(keysDir)
	if err != nil {
		appLogger.Error("Error creating key store", logger.NewField("error", err.Error()))
		log.Fatalf("Error creating key store: %v", err)
	}

	// Инициализируем ключи для всех поддерживаемых алгоритмов
	if err := keyStore.InitializeKeys(cfg.App.Token.AlgSupported); err != nil {
		appLogger.Error("Error initializing keys", logger.NewField("error", err.Error()))
		log.Fatalf("Error initializing keys: %v", err)
	}

	appLogger.Info("Keys initialized")

	// Создаем клиент Redis
	redisClient, err := redis.NewClient(cfg.App.Redis)
	if err != nil {
		appLogger.Error("Error connecting to Redis", logger.NewField("error", err.Error()))
		log.Fatalf("Error connecting to Redis: %v", err)
	}
	defer redisClient.Close()

	appLogger.Info("Redis connection established")

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
	mux.HandleFunc(
		"/api/v1/tokens/generate",
		handleGenerateTokens(authService, appLogger, cfg.App),
	)
	mux.HandleFunc(
		"/api/v1/tokens/refresh",
		handleRefreshTokens(authService, appLogger, cfg.App),
	)

	// Все остальные запросы идут в proxy
	mux.HandleFunc("/", handleProxy(proxyService, appLogger, cfg.App))

	// Обертываем в middleware для логирования
	handler := loggingMiddleware(mux, appLogger)

	server.Handler = handler

	// Запускаем сервер в отдельной горутине
	go func() {
		appLogger.Info("HTTP server started", logger.NewField("addr", server.Addr))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			appLogger.Error("HTTP server error", logger.NewField("error", err.Error()))
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Ожидаем сигнал для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	appLogger.Info("Received shutdown signal, starting graceful shutdown")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		appLogger.Error("Error during server shutdown", logger.NewField("error", err.Error()))
		log.Fatalf("Error during server shutdown: %v", err)
	}

	appLogger.Info("Server stopped")
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
