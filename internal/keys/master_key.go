package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	minMasterKeySize = 32 // 256 бит
)

// loadMasterKey загружает мастер-ключ из переменной окружения или файла
func loadMasterKey(keysDir string) ([]byte, error) {
	// Сначала проверяем переменную окружения
	if masterKeyEnv := os.Getenv("MASTER_KEY"); masterKeyEnv != "" {
		// Может быть в base64 или в виде строки
		key, err := base64.StdEncoding.DecodeString(masterKeyEnv)
		if err != nil {
			// Если не base64, используем как есть
			key = []byte(masterKeyEnv)
		}

		if len(key) < minMasterKeySize {
			return nil, fmt.Errorf("мастер-ключ из MASTER_KEY слишком короткий (минимум %d байт)", minMasterKeySize)
		}

		return key, nil
	}

	// Проверяем файл master.key
	masterKeyPath := filepath.Join(keysDir, "master.key")
	data, err := os.ReadFile(masterKeyPath)
	if err == nil {
		// Файл существует, читаем его
		key, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			// Если не base64, используем как есть
			key = data
		}

		if len(key) < minMasterKeySize {
			return nil, fmt.Errorf("мастер-ключ из файла слишком короткий (минимум %d байт)", minMasterKeySize)
		}

		return key, nil
	}

	// Мастер-ключ не найден, генерируем новый
	return generateAndSaveMasterKey(masterKeyPath)
}

// generateAndSaveMasterKey генерирует новый мастер-ключ и сохраняет его в файл
func generateAndSaveMasterKey(path string) ([]byte, error) {
	// Генерируем случайный ключ длиной 32 байта (256 бит)
	key := make([]byte, minMasterKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("ошибка генерации мастер-ключа: %w", err)
	}

	// Кодируем в base64 для сохранения
	encoded := base64.StdEncoding.EncodeToString(key)

	// Сохраняем в файл с правами 0600
	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return nil, fmt.Errorf("ошибка сохранения мастер-ключа: %w", err)
	}

	// Выводим предупреждение
	fmt.Fprintf(os.Stderr, "WARNING: Сгенерирован новый мастер-ключ. Сохраните его для последующих запусков:\n")
	fmt.Fprintf(os.Stderr, "  MASTER_KEY=%s\n", encoded)
	fmt.Fprintf(os.Stderr, "  или файл: %s\n", path)

	return key, nil
}

