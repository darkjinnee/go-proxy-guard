package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// LoadAppConfigWithEnv загружает конфигурацию из файла и переопределяет значения из .env
func LoadAppConfigWithEnv(path string) (*AppConfig, error) {
	// Загружаем .env файл (если существует, игнорируем ошибку)
	_ = godotenv.Load()

	// Загружаем базовую конфигурацию
	cfg, err := LoadAppConfig(path)
	if err != nil {
		return nil, err
	}

	// Переопределяем значения из переменных окружения
	overrideFromEnv(cfg)

	// Валидируем финальную конфигурацию
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("error validating config after applying environment variables: %w", err)
	}

	return cfg, nil
}

// overrideFromEnv переопределяет значения конфигурации из переменных окружения
func overrideFromEnv(cfg *AppConfig) {
	// Proxy настройки
	if v := os.Getenv("PROXY_TIMEOUT_MS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.TimeoutMS = i
		}
	}
	if v := os.Getenv("PROXY_MAX_BODY_SIZE_MB"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.MaxBodySizeMB = i
		}
	}

	// Token настройки
	if v := os.Getenv("TOKEN_EXP"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Token.Exp = i
		}
	}
	if v := os.Getenv("TOKEN_REFRESH_EXP"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Token.RefreshExp = i
		}
	}
	if v := os.Getenv("TOKEN_MAX_JWT_SIZE_BYTES"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Token.MaxJWTSizeBytes = i
		}
	}
	if v := os.Getenv("TOKEN_ALG_SUPPORTED"); v != "" {
		cfg.Token.AlgSupported = strings.Split(v, ",")
		for i := range cfg.Token.AlgSupported {
			cfg.Token.AlgSupported[i] = strings.TrimSpace(cfg.Token.AlgSupported[i])
		}
	}
	if v := os.Getenv("TOKEN_TYP_SUPPORTED"); v != "" {
		cfg.Token.TypSupported = strings.Split(v, ",")
		for i := range cfg.Token.TypSupported {
			cfg.Token.TypSupported[i] = strings.TrimSpace(cfg.Token.TypSupported[i])
		}
	}
	if v := os.Getenv("TOKEN_IP_WHITELIST"); v != "" {
		cfg.Token.IPWhitelist = strings.Split(v, ",")
		for i := range cfg.Token.IPWhitelist {
			cfg.Token.IPWhitelist[i] = strings.TrimSpace(cfg.Token.IPWhitelist[i])
		}
	}

	// Redis настройки
	if v := os.Getenv("REDIS_HOST"); v != "" {
		cfg.Redis.Host = v
	}
	if v := os.Getenv("REDIS_PORT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Redis.Port = i
		}
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("REDIS_DB"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Redis.DB = i
		}
	}
	if v := os.Getenv("REDIS_KEY_PREFIX"); v != "" {
		cfg.Redis.KeyPrefix = v
	}

	// Logging настройки
	if v := os.Getenv("LOGGING_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("LOGGING_OUTPUT"); v != "" {
		cfg.Logging.Output = v
	}
	if v := os.Getenv("LOGGING_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	if v := os.Getenv("LOGGING_ROTATION_MAX_SIZE_MB"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Logging.Rotation.MaxSizeMB = i
		}
	}
	if v := os.Getenv("LOGGING_ROTATION_MAX_AGE_DAYS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Logging.Rotation.MaxAgeDays = i
		}
	}
	if v := os.Getenv("LOGGING_ROTATION_MAX_BACKUPS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			cfg.Logging.Rotation.MaxBackups = i
		}
	}
	if v := os.Getenv("LOGGING_ROTATION_COMPRESS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Logging.Rotation.Compress = b
		}
	}

	// Keys настройки
	if v := os.Getenv("KEYS_DIR"); v != "" {
		cfg.Keys.Dir = v
	}
}

