package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-proxy-guard/internal/config"
)

func TestNew(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	cfg := config.LoggingConfig{
		Level:  "info",
		Output: logPath,
		Format: "json",
		Rotation: config.RotationConfig{
			MaxSizeMB:  10,
			MaxAgeDays: 7,
			MaxBackups: 5,
			Compress:   false,
		},
	}

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания логгера: %v", err)
	}

	if logger == nil {
		t.Fatal("Логгер не создан")
	}

	// Проверяем, что файл создан
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatal("Файл лога не создан")
	}
}

func TestLogger_Levels(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	cfg := config.LoggingConfig{
		Level:  "info",
		Output: logPath,
		Format: "text",
		Rotation: config.RotationConfig{
			MaxSizeMB:  10,
			MaxAgeDays: 7,
			MaxBackups: 5,
			Compress:   false,
		},
	}

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания логгера: %v", err)
	}

	// Debug не должен логироваться (уровень info)
	logger.Debug("debug message", NewField("test", "value"))

	// Info должен логироваться
	logger.Info("info message", NewField("test", "value"))

	// Warn должен логироваться
	logger.Warn("warn message", NewField("test", "value"))

	// Error должен логироваться
	logger.Error("error message", NewField("test", "value"))

	// Проверяем содержимое файла
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Ошибка чтения файла лога: %v", err)
	}

	content := string(data)
	if !contains(content, "info message") {
		t.Error("Сообщение info не найдено в логе")
	}
	if !contains(content, "warn message") {
		t.Error("Сообщение warn не найдено в логе")
	}
	if !contains(content, "error message") {
		t.Error("Сообщение error не найдено в логе")
	}
	if contains(content, "debug message") {
		t.Error("Сообщение debug не должно быть в логе (уровень info)")
	}
}

func TestLogger_With(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	cfg := config.LoggingConfig{
		Level:  "info",
		Output: logPath,
		Format: "text",
		Rotation: config.RotationConfig{
			MaxSizeMB:  10,
			MaxAgeDays: 7,
			MaxBackups: 5,
			Compress:   false,
		},
	}

	logger, err := New(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания логгера: %v", err)
	}

	// Создаем логгер с дополнительными полями
	loggerWithFields := logger.With(
		NewField("service", "test"),
		NewField("version", "1.0"),
	)

	loggerWithFields.Info("test message", NewField("action", "test"))

	// Проверяем содержимое файла
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Ошибка чтения файла лога: %v", err)
	}

	content := string(data)
	if !contains(content, "service=test") {
		t.Error("Поле service не найдено в логе")
	}
	if !contains(content, "version=1.0") {
		t.Error("Поле version не найдено в логе")
	}
	if !contains(content, "action=test") {
		t.Error("Поле action не найдено в логе")
	}
}

func TestLogger_Formats(t *testing.T) {
	tests := []struct {
		name   string
		format string
		check  func(string) bool
	}{
		{
			name:   "JSON формат",
			format: "json",
			check: func(content string) bool {
				return contains(content, "\"level\"") && contains(content, "\"message\"")
			},
		},
		{
			name:   "Text формат",
			format: "text",
			check: func(content string) bool {
				return contains(content, "[INFO]") && contains(content, "test message")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			logPath := filepath.Join(tmpDir, "test.log")

			cfg := config.LoggingConfig{
				Level:  "info",
				Output: logPath,
				Format: tt.format,
				Rotation: config.RotationConfig{
					MaxSizeMB:  10,
					MaxAgeDays: 7,
					MaxBackups: 5,
					Compress:   false,
				},
			}

			logger, err := New(cfg)
			if err != nil {
				t.Fatalf("Ошибка создания логгера: %v", err)
			}

			logger.Info("test message", NewField("key", "value"))

			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("Ошибка чтения файла лога: %v", err)
			}

			if !tt.check(string(data)) {
				t.Errorf("Формат %s не соответствует ожиданиям", tt.format)
			}
		})
	}
}

func TestMaskToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "длинный токен",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzNDUiLCJ1c2VybmFtZSI6ImpvaG5kb2UiLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: "eyJhbGciOi...",
		},
		{
			name:     "короткий токен",
			token:    "short",
			expected: "*****",
		},
		{
			name:     "пустой токен",
			token:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskToken(tt.token)
			if result != tt.expected {
				t.Errorf("maskToken(%q) = %q, ожидалось %q", tt.token, result, tt.expected)
			}
		})
	}
}

func TestSanitizeValue(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    interface{}
		expected interface{}
	}{
		{
			name:     "токен маскируется",
			key:      "access_token",
			value:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			expected: "eyJhbGciOi...",
		},
		{
			name:     "ключ скрывается",
			key:      "secret_key",
			value:    "my-secret-key",
			expected: "[REDACTED]",
		},
		{
			name:     "пароль скрывается",
			key:      "password",
			value:    "my-password",
			expected: "[REDACTED]",
		},
		{
			name:     "обычное значение не изменяется",
			key:      "user_id",
			value:    "12345",
			expected: "12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeValue(tt.key, tt.value)
			if result != tt.expected {
				t.Errorf("sanitizeValue(%q, %v) = %v, ожидалось %v", tt.key, tt.value, result, tt.expected)
			}
		})
	}
}

// contains проверяет, содержит ли строка подстроку
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
