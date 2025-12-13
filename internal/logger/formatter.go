package logger

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Formatter представляет интерфейс форматирования логов
type Formatter interface {
	Format(entry *LogEntry) ([]byte, error)
}

// jsonFormatter форматирует логи в JSON
type jsonFormatter struct{}

func newJSONFormatter() Formatter {
	return &jsonFormatter{}
}

func (f *jsonFormatter) Format(entry *LogEntry) ([]byte, error) {
	data := make(map[string]interface{})
	data["timestamp"] = entry.Timestamp.Format(time.RFC3339)
	data["level"] = entry.Level
	data["message"] = entry.Message

	// Добавляем поля
	for _, field := range entry.Fields {
		// Безопасное добавление значения (маскирование токенов и ключей)
		data[field.Key] = sanitizeValue(field.Key, field.Value)
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %w", err)
	}

	return append(jsonData, '\n'), nil
}

// textFormatter форматирует логи в текстовый формат
type textFormatter struct{}

func newTextFormatter() Formatter {
	return &textFormatter{}
}

func (f *textFormatter) Format(entry *LogEntry) ([]byte, error) {
	var parts []string

	// Timestamp
	parts = append(parts, entry.Timestamp.Format(time.RFC3339))

	// Level
	parts = append(parts, fmt.Sprintf("[%s]", strings.ToUpper(entry.Level)))

	// Message
	parts = append(parts, entry.Message)

	// Fields
	for _, field := range entry.Fields {
		value := sanitizeValue(field.Key, field.Value)
		parts = append(parts, fmt.Sprintf("%s=%v", field.Key, value))
	}

	result := strings.Join(parts, " ") + "\n"
	return []byte(result), nil
}

// sanitizeValue маскирует чувствительные данные
func sanitizeValue(key string, value interface{}) interface{} {
	keyLower := strings.ToLower(key)

	// Маскирование токенов
	if strings.Contains(keyLower, "token") {
		if str, ok := value.(string); ok {
			return maskToken(str)
		}
	}

	// Не логируем ключи, пароли и мастер-ключи
	if strings.Contains(keyLower, "key") ||
		strings.Contains(keyLower, "password") ||
		strings.Contains(keyLower, "master_key") ||
		strings.Contains(keyLower, "secret") {
		return "[REDACTED]"
	}

	return value
}

// maskToken маскирует JWT токен, оставляя только первые 10 символов
func maskToken(token string) string {
	if len(token) == 0 {
		return token
	}

	if len(token) <= 10 {
		return strings.Repeat("*", len(token))
	}

	return token[:10] + "..."
}
