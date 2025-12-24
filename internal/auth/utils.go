package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"go-proxy-guard/internal/keys"
)

// generateUUID генерирует UUID v4
func generateUUID() string {
	uuid := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, uuid); err != nil {
		panic(fmt.Sprintf("error generating UUID: %v", err))
	}

	// Устанавливаем версию (4) и вариант
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Версия 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Вариант 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// extractAlgorithmFromToken извлекает алгоритм из header токена
func extractAlgorithmFromToken(tokenString string) (keys.Algorithm, error) {
	// JWT токен состоит из трех частей, разделенных точками
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid token format")
	}

	// Декодируем header (первая часть)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("error decoding header: %w", err)
	}

	// Парсим JSON header
	// Простой парсинг для извлечения "alg"
	headerStr := string(headerBytes)
	if !strings.Contains(headerStr, `"alg"`) {
		return "", fmt.Errorf("header does not contain alg")
	}

	// Извлекаем значение alg
	algStart := strings.Index(headerStr, `"alg"`)
	if algStart == -1 {
		return "", fmt.Errorf("alg not found in header")
	}

	// Ищем значение после "alg":
	valueStart := strings.Index(headerStr[algStart:], `:`)
	if valueStart == -1 {
		return "", fmt.Errorf("invalid alg format in header")
	}

	valueStart += algStart + 1
	// Пропускаем пробелы и кавычки
	for valueStart < len(headerStr) && (headerStr[valueStart] == ' ' || headerStr[valueStart] == '"') {
		valueStart++
	}

	valueEnd := valueStart
	for valueEnd < len(headerStr) && headerStr[valueEnd] != '"' && headerStr[valueEnd] != ',' && headerStr[valueEnd] != '}' {
		valueEnd++
	}

	alg := headerStr[valueStart:valueEnd]
	return keys.Algorithm(alg), nil
}

// extractKidFromToken извлекает kid из header токена
func extractKidFromToken(tokenString string) string {
	// JWT токен состоит из трех частей, разделенных точками
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return ""
	}

	// Декодируем header (первая часть)
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}

	// Парсим JSON header для извлечения "kid"
	headerStr := string(headerBytes)
	if !strings.Contains(headerStr, `"kid"`) {
		return ""
	}

	// Извлекаем значение kid
	kidStart := strings.Index(headerStr, `"kid"`)
	if kidStart == -1 {
		return ""
	}

	// Ищем значение после "kid":
	valueStart := strings.Index(headerStr[kidStart:], `:`)
	if valueStart == -1 {
		return ""
	}

	valueStart += kidStart + 1
	// Пропускаем пробелы и кавычки
	for valueStart < len(headerStr) && (headerStr[valueStart] == ' ' || headerStr[valueStart] == '"') {
		valueStart++
	}

	valueEnd := valueStart
	for valueEnd < len(headerStr) && headerStr[valueEnd] != '"' && headerStr[valueEnd] != ',' && headerStr[valueEnd] != '}' {
		valueEnd++
	}

	if valueEnd > valueStart {
		return headerStr[valueStart:valueEnd]
	}

	return ""
}
