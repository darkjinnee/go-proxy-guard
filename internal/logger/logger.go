package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go-proxy-guard/internal/config"
)

// Level представляет уровень логирования
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = map[Level]string{
	LevelDebug: "debug",
	LevelInfo:  "info",
	LevelWarn:  "warn",
	LevelError: "error",
}

var nameToLevel = map[string]Level{
	"debug": LevelDebug,
	"info":  LevelInfo,
	"warn":  LevelWarn,
	"error": LevelError,
}

// Logger представляет интерфейс логирования
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	With(fields ...Field) Logger
}

// Field представляет поле лога
type Field struct {
	Key   string
	Value interface{}
}

// NewField создает новое поле лога
func NewField(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// loggerImpl реализует интерфейс Logger
type loggerImpl struct {
	level     Level
	formatter Formatter
	writer    io.Writer
	fields    []Field
	mu        sync.Mutex
	rotation  *rotationManager
}

// New создает новый логгер на основе конфигурации
func New(cfg config.LoggingConfig) (Logger, error) {
	level, ok := nameToLevel[cfg.Level]
	if !ok {
		return nil, fmt.Errorf("invalid logging level: %s", cfg.Level)
	}

	// Создаем директорию для логов, если не существует
	dir := filepath.Dir(cfg.Output)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("error creating log directory: %w", err)
	}

	// Открываем файл для записи
	file, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening log file: %w", err)
	}

	// Создаем менеджер ротации
	rotation, err := newRotationManager(cfg.Output, cfg.Rotation)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("error creating rotation manager: %w", err)
	}

	// Создаем форматтер
	var formatter Formatter
	switch cfg.Format {
	case "json":
		formatter = newJSONFormatter()
	case "text":
		formatter = newTextFormatter()
	default:
		file.Close()
		return nil, fmt.Errorf("invalid logging format: %s", cfg.Format)
	}

	return &loggerImpl{
		level:     level,
		formatter: formatter,
		writer:    file,
		rotation:  rotation,
	}, nil
}

// Debug логирует сообщение на уровне debug
func (l *loggerImpl) Debug(msg string, fields ...Field) {
	l.log(LevelDebug, msg, fields...)
}

// Info логирует сообщение на уровне info
func (l *loggerImpl) Info(msg string, fields ...Field) {
	l.log(LevelInfo, msg, fields...)
}

// Warn логирует сообщение на уровне warn
func (l *loggerImpl) Warn(msg string, fields ...Field) {
	l.log(LevelWarn, msg, fields...)
}

// Error логирует сообщение на уровне error
func (l *loggerImpl) Error(msg string, fields ...Field) {
	l.log(LevelError, msg, fields...)
}

// With создает новый логгер с дополнительными полями
func (l *loggerImpl) With(fields ...Field) Logger {
	return &loggerImpl{
		level:     l.level,
		formatter: l.formatter,
		writer:    l.writer,
		fields:    append(l.fields, fields...),
		rotation:  l.rotation,
	}
}

// log выполняет логирование сообщения
func (l *loggerImpl) log(level Level, msg string, fields ...Field) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Проверяем необходимость ротации
	if l.rotation != nil {
		if err := l.rotation.checkAndRotate(); err != nil {
			// Логируем ошибку ротации, но не прерываем логирование
			fmt.Fprintf(os.Stderr, "Error rotating logs: %v\n", err)
		}
	}

	// Объединяем все поля
	allFields := append(l.fields, fields...)

	// Форматируем и записываем
	entry := &LogEntry{
		Timestamp: time.Now().UTC(),
		Level:     levelNames[level],
		Message:   msg,
		Fields:    allFields,
	}

	formatted, err := l.formatter.Format(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting log: %v\n", err)
		return
	}

	if _, err := l.writer.Write(formatted); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing log: %v\n", err)
	}
}

// LogEntry представляет запись лога
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
	Fields    []Field
}
