package keys

import (
	"fmt"
)

// InitializeKeys генерирует ключи для всех указанных алгоритмов, если они еще не существуют
func (s *FileStore) InitializeKeys(algorithms []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, algStr := range algorithms {
		algorithm := Algorithm(algStr)

		// Проверяем, существует ли уже ключ для этого алгоритма
		if _, exists := s.keys[algorithm]; exists {
			continue // Ключ уже существует
		}

		// Генерируем новый ключ
		key, err := GenerateKey(algorithm)
		if err != nil {
			return fmt.Errorf("ошибка генерации ключа для %s: %w", algorithm, err)
		}

		// Сохраняем ключ
		if err := s.saveKey(key); err != nil {
			return fmt.Errorf("ошибка сохранения ключа для %s: %w", algorithm, err)
		}

		// Обновляем кэш
		s.keys[algorithm] = key
		s.keysByID[key.Metadata.ID] = key
	}

	return nil
}

