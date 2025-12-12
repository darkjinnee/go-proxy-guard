package config

import (
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	appPath := filepath.Join("..", "..", "configs", "app.json")
	proxyPath := filepath.Join("..", "..", "configs", "proxy.json")

	cfg, err := LoadConfig(appPath, proxyPath)
	if err != nil {
		t.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	if cfg.App == nil {
		t.Fatal("App конфигурация не загружена")
	}

	if cfg.Proxy == nil {
		t.Fatal("Proxy конфигурация не загружена")
	}

	// Проверка, что конфигурация валидна
	if err := cfg.App.Validate(); err != nil {
		t.Errorf("App конфигурация невалидна: %v", err)
	}

	if err := cfg.Proxy.Validate(); err != nil {
		t.Errorf("Proxy конфигурация невалидна: %v", err)
	}
}
