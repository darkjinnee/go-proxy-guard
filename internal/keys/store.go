package keys

import (
	"fmt"
	"os"
	"sync"
)

// FileStore представляет файловое хранилище ключей
type FileStore struct {
	keysDir    string
	masterKey  []byte
	keys       map[Algorithm]*Key
	keysByID   map[string]*Key
	mu         sync.RWMutex
}

// NewFileStore создает новое файловое хранилище ключей
func NewFileStore(keysDir string) (*FileStore, error) {
	// Создаем директорию, если не существует
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("ошибка создания директории ключей: %w", err)
	}

	// Загружаем мастер-ключ
	masterKey, err := loadMasterKey(keysDir)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки мастер-ключа: %w", err)
	}

	store := &FileStore{
		keysDir:   keysDir,
		masterKey: masterKey,
		keys:      make(map[Algorithm]*Key),
		keysByID:  make(map[string]*Key),
	}

	// Загружаем существующие ключи
	if err := store.loadKeys(); err != nil {
		return nil, fmt.Errorf("ошибка загрузки ключей: %w", err)
	}

	return store, nil
}

// GetKey возвращает активный ключ для указанного алгоритма
func (s *FileStore) GetKey(algorithm Algorithm) (*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keys[algorithm]
	if !exists {
		return nil, fmt.Errorf("ключ для алгоритма %s не найден", algorithm)
	}

	return key, nil
}

// GetKeyByID возвращает ключ по идентификатору
func (s *FileStore) GetKeyByID(id string) (*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keysByID[id]
	if !exists {
		return nil, fmt.Errorf("ключ с ID %s не найден", id)
	}

	return key, nil
}

// GenerateKey генерирует новый ключ для указанного алгоритма
func (s *FileStore) GenerateKey(algorithm Algorithm) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Генерируем новый ключ
	key, err := GenerateKey(algorithm)
	if err != nil {
		return nil, err
	}

	// Сохраняем ключ
	if err := s.saveKey(key); err != nil {
		return nil, fmt.Errorf("ошибка сохранения ключа: %w", err)
	}

	// Обновляем кэш
	s.keys[algorithm] = key
	s.keysByID[key.Metadata.ID] = key

	return key, nil
}

// RegenerateKey регенерирует ключ для указанного алгоритма
func (s *FileStore) RegenerateKey(algorithm Algorithm) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Создаем резервную копию старого ключа, если он существует
	if oldKey, exists := s.keys[algorithm]; exists {
		if err := s.backupKey(oldKey); err != nil {
			return nil, fmt.Errorf("ошибка создания резервной копии: %w", err)
		}
		oldKey.Metadata.Status = StatusBackup
	}

	// Генерируем новый ключ
	key, err := GenerateKey(algorithm)
	if err != nil {
		return nil, err
	}

	// Сохраняем новый ключ
	if err := s.saveKey(key); err != nil {
		return nil, fmt.Errorf("ошибка сохранения ключа: %w", err)
	}

	// Обновляем кэш
	s.keys[algorithm] = key
	s.keysByID[key.Metadata.ID] = key

	return key, nil
}

// ListKeys возвращает список всех ключей
func (s *FileStore) ListKeys() ([]KeyMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var metadata []KeyMetadata
	for _, key := range s.keysByID {
		metadata = append(metadata, key.Metadata)
	}

	return metadata, nil
}

