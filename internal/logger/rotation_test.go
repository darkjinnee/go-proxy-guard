package logger

import (
	"os"
	"path/filepath"
	"testing"

	"go-proxy-guard/internal/config"
)

func TestRotationManager(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	cfg := config.LoggingConfig{
		Level:  "info",
		Output: logPath,
		Format: "text",
		Rotation: config.RotationConfig{
			MaxSizeMB:  1, // 1 MB для теста
			MaxAgeDays: 7,
			MaxBackups: 5,
			Compress:   false,
		},
	}

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания логгера: %v", err)
	}

	// Заполняем файл до размера, превышающего лимит
	// Записываем много сообщений
	for i := 0; i < 1000; i++ {
		logger.Info("test message", NewField("iteration", i))
	}

	// Проверяем, что файл существует
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatal("Файл лога не создан")
	}
}

func TestRotationManager_Compress(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	cfg := config.LoggingConfig{
		Level:  "info",
		Output: logPath,
		Format: "text",
		Rotation: config.RotationConfig{
			MaxSizeMB:  1,
			MaxAgeDays: 7,
			MaxBackups: 5,
			Compress:   true,
		},
	}

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания логгера: %v", err)
	}

	// Заполняем файл
	for i := 0; i < 1000; i++ {
		logger.Info("test message", NewField("iteration", i))
	}

	// Проверяем, что файл существует
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatal("Файл лога не создан")
	}
}
