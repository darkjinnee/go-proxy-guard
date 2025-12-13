package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// AppConfig представляет глобальную конфигурацию приложения
type AppConfig struct {
	Proxy   ProxyConfig   `json:"proxy"`
	Token   TokenConfig   `json:"token"`
	Redis   RedisConfig   `json:"redis"`
	Logging LoggingConfig `json:"logging"`
	Keys    KeysConfig    `json:"keys"`
}

// KeysConfig представляет настройки управления ключами
type KeysConfig struct {
	Dir string `json:"dir"`
}

// Validate проверяет корректность настроек ключей
func (c *KeysConfig) Validate() error {
	if c.Dir == "" {
		return fmt.Errorf("dir cannot be empty")
	}

	return nil
}

// ProxyConfig представляет настройки проксирования
type ProxyConfig struct {
	TimeoutMS      int               `json:"timeout_ms"`
	MaxBodySizeMB  int               `json:"max_body_size_mb"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty"`
}

// TokenConfig представляет настройки JWT токенов
type TokenConfig struct {
	Exp             int      `json:"exp"`
	RefreshExp      int      `json:"refresh_exp"`
	MaxJWTSizeBytes int      `json:"max_jwt_size_bytes"`
	AlgSupported    []string `json:"alg_supported"`
	TypSupported    []string `json:"typ_supported"`
	IPWhitelist     []string `json:"ip_whitelist,omitempty"`
}

// RedisConfig представляет настройки подключения к Redis
type RedisConfig struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Password  string `json:"password,omitempty"`
	DB        int    `json:"db"`
	KeyPrefix string `json:"key_prefix"`
}

// LoggingConfig представляет настройки логирования
type LoggingConfig struct {
	Level    string         `json:"level"`
	Output   string         `json:"output"`
	Rotation RotationConfig `json:"rotation"`
	Format   string         `json:"format"`
}

// RotationConfig представляет настройки ротации логов
type RotationConfig struct {
	MaxSizeMB  int  `json:"max_size_mb"`
	MaxAgeDays int  `json:"max_age_days"`
	MaxBackups int  `json:"max_backups"`
	Compress   bool `json:"compress"`
}

// LoadAppConfig загружает конфигурацию приложения из файла
func LoadAppConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("error validating config: %w", err)
	}

	return &cfg, nil
}

// Validate проверяет корректность конфигурации приложения
func (c *AppConfig) Validate() error {
	if err := c.Proxy.Validate(); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}

	if err := c.Token.Validate(); err != nil {
		return fmt.Errorf("token: %w", err)
	}

	if err := c.Redis.Validate(); err != nil {
		return fmt.Errorf("redis: %w", err)
	}

	if err := c.Logging.Validate(); err != nil {
		return fmt.Errorf("logging: %w", err)
	}

	if err := c.Keys.Validate(); err != nil {
		return fmt.Errorf("keys: %w", err)
	}

	return nil
}

// Validate проверяет корректность настроек проксирования
func (c *ProxyConfig) Validate() error {
	if c.TimeoutMS <= 0 {
		return fmt.Errorf("timeout_ms must be greater than 0")
	}

	if c.MaxBodySizeMB <= 0 {
		return fmt.Errorf("max_body_size_mb must be greater than 0")
	}

	return nil
}

// Validate проверяет корректность настроек токенов
func (c *TokenConfig) Validate() error {
	if c.Exp <= 0 {
		return fmt.Errorf("exp must be greater than 0")
	}

	if c.RefreshExp <= 0 {
		return fmt.Errorf("refresh_exp must be greater than 0")
	}

	if c.MaxJWTSizeBytes <= 0 {
		return fmt.Errorf("max_jwt_size_bytes must be greater than 0")
	}

	if len(c.AlgSupported) == 0 {
		return fmt.Errorf("alg_supported cannot be empty")
	}

	if len(c.TypSupported) == 0 {
		return fmt.Errorf("typ_supported cannot be empty")
	}

	return nil
}

// Validate проверяет корректность настроек Redis
func (c *RedisConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("port must be in range 1-65535")
	}

	if c.DB < 0 {
		return fmt.Errorf("db cannot be negative")
	}

	return nil
}

// Validate проверяет корректность настроек логирования
func (c *LoggingConfig) Validate() error {
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}

	if !validLevels[c.Level] {
		return fmt.Errorf("invalid logging level: %s", c.Level)
	}

	if c.Output == "" {
		return fmt.Errorf("output cannot be empty")
	}

	validFormats := map[string]bool{
		"json": true,
		"text": true,
	}

	if !validFormats[c.Format] {
		return fmt.Errorf("invalid logging format: %s", c.Format)
	}

	if err := c.Rotation.Validate(); err != nil {
		return fmt.Errorf("rotation: %w", err)
	}

	return nil
}

// Validate проверяет корректность настроек ротации логов
func (c *RotationConfig) Validate() error {
	if c.MaxSizeMB <= 0 {
		return fmt.Errorf("max_size_mb must be greater than 0")
	}

	if c.MaxAgeDays <= 0 {
		return fmt.Errorf("max_age_days must be greater than 0")
	}

	if c.MaxBackups < 0 {
		return fmt.Errorf("max_backups cannot be negative")
	}

	return nil
}
