package keys

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// loadKeys загружает все ключи из директории
func (s *FileStore) loadKeys() error {
	entries, err := os.ReadDir(s.keysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Директория не существует, ключей нет
		}
		return fmt.Errorf("ошибка чтения директории: %w", err)
	}

	// Собираем ключи по ID
	keyFiles := make(map[string][]string)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Пропускаем мастер-ключ и резервные копии
		if name == "master.key" || strings.HasSuffix(name, ".backup") {
			continue
		}

		// Парсим имя файла для извлечения ID
		var keyID string
		if _, kid, ok := parseRSAKeyFilename(name); ok {
			keyID = kid
		} else if _, kid, ok := parseESKeyFilename(name); ok {
			keyID = kid
		}

		if keyID == "" {
			continue
		}

		if keyFiles[keyID] == nil {
			keyFiles[keyID] = []string{}
		}
		keyFiles[keyID] = append(keyFiles[keyID], name)
	}

	// Загружаем ключи
	for keyID, files := range keyFiles {
		// Определяем алгоритм по первому файлу
		var algorithm Algorithm
		firstFile := files[0]
		if alg, _, ok := parseRSAKeyFilename(firstFile); ok {
			algorithm = alg
		} else if alg, _, ok := parseESKeyFilename(firstFile); ok {
			algorithm = alg
		} else {
			continue
		}

		key, err := s.loadKey(keyID, algorithm)
		if err != nil {
			// Пропускаем ключи, которые не удалось загрузить
			continue
		}

		// Сохраняем в кэш
		s.keys[algorithm] = key
		s.keysByID[keyID] = key
	}

	return nil
}

// loadKey загружает ключ по ID и алгоритму
func (s *FileStore) loadKey(keyID string, algorithm Algorithm) (*Key, error) {
	metadata := KeyMetadata{
		ID:        keyID,
		Algorithm: algorithm,
		Status:    StatusActive,
	}

	key := &Key{
		Metadata: metadata,
	}

	switch algorithm {
	case AlgorithmRS256, AlgorithmRS512:
		keyPair, err := s.loadRSAKey(keyID, algorithm)
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	case AlgorithmES256, AlgorithmES512:
		keyPair, err := s.loadECDSAKey(keyID, algorithm)
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм: %s", algorithm)
	}

	return key, nil
}

// loadRSAKey загружает RSA ключ (файлы rsa256_<id>.* или rsa512_<id>.*).
func (s *FileStore) loadRSAKey(keyID string, algorithm Algorithm) (*KeyPair, error) {
	prefix, err := rsaNamePrefix(algorithm)
	if err != nil {
		return nil, err
	}

	privateFilename := fmt.Sprintf("%s%s.private", prefix, keyID)
	privatePath := filepath.Join(s.keysDir, privateFilename)

	encryptedPrivate, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения приватного ключа: %w", err)
	}

	// Расшифровываем приватный ключ
	privatePEM, err := decryptData(encryptedPrivate, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки приватного ключа: %w", err)
	}

	// Декодируем PEM
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, fmt.Errorf("ошибка декодирования PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга приватного ключа: %w", err)
	}

	return &KeyPair{
		Private: privateKey,
		Public:  privateKey.Public(),
	}, nil
}

// loadECDSAKey загружает ECDSA ключ (es256_<id>.* или es512_<id>.*).
func (s *FileStore) loadECDSAKey(keyID string, algorithm Algorithm) (*KeyPair, error) {
	prefix, err := esNamePrefix(algorithm)
	if err != nil {
		return nil, err
	}

	privateFilename := fmt.Sprintf("%s%s.private", prefix, keyID)
	privatePath := filepath.Join(s.keysDir, privateFilename)

	encryptedPrivate, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения приватного ключа: %w", err)
	}

	// Расшифровываем приватный ключ
	privatePEM, err := decryptData(encryptedPrivate, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки приватного ключа: %w", err)
	}

	// Декодируем PEM
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, fmt.Errorf("ошибка декодирования PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга приватного ключа: %w", err)
	}

	return &KeyPair{
		Private: privateKey,
		Public:  privateKey.Public(),
	}, nil
}
