package keys

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
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
		if strings.HasPrefix(name, "hmac_") && strings.HasSuffix(name, ".key") {
			keyID = strings.TrimPrefix(strings.TrimSuffix(name, ".key"), "hmac_")
		} else if strings.HasPrefix(name, "rsa_") {
			parts := strings.Split(strings.TrimSuffix(strings.TrimSuffix(name, ".private"), ".public"), "_")
			if len(parts) == 2 {
				keyID = parts[1]
			}
		} else if strings.HasPrefix(name, "ecdsa_") {
			parts := strings.Split(strings.TrimSuffix(strings.TrimSuffix(name, ".private"), ".public"), "_")
			if len(parts) == 2 {
				keyID = parts[1]
			}
		} else if strings.HasPrefix(name, "eddsa_") {
			parts := strings.Split(strings.TrimSuffix(strings.TrimSuffix(name, ".private"), ".public"), "_")
			if len(parts) == 2 {
				keyID = parts[1]
			}
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
		if strings.HasPrefix(firstFile, "hmac_") {
			algorithm = AlgorithmHS256
		} else if strings.HasPrefix(firstFile, "rsa_") {
			algorithm = AlgorithmRS256 // Можно определить точнее по размеру ключа
		} else if strings.HasPrefix(firstFile, "ecdsa_") {
			algorithm = AlgorithmES256
		} else if strings.HasPrefix(firstFile, "eddsa_") {
			algorithm = AlgorithmEdDSA
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
	case AlgorithmHS256:
		hmacKey, err := s.loadHMACKey(keyID)
		if err != nil {
			return nil, err
		}
		key.HMAC = hmacKey

	case AlgorithmRS256, AlgorithmRS512:
		keyPair, err := s.loadRSAKey(keyID)
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	case AlgorithmES256:
		keyPair, err := s.loadECDSAKey(keyID)
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	case AlgorithmEdDSA:
		keyPair, err := s.loadEdDSAKey(keyID)
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм: %s", algorithm)
	}

	return key, nil
}

// loadHMACKey загружает HMAC ключ
func (s *FileStore) loadHMACKey(keyID string) ([]byte, error) {
	filename := fmt.Sprintf("hmac_%s.key", keyID)
	path := filepath.Join(s.keysDir, filename)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла: %w", err)
	}

	// Декодируем из base64
	encrypted, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования base64: %w", err)
	}

	// Расшифровываем
	decrypted, err := decryptData(encrypted, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	return decrypted, nil
}

// loadRSAKey загружает RSA ключ
func (s *FileStore) loadRSAKey(keyID string) (*KeyPair, error) {
	privateFilename := fmt.Sprintf("rsa_%s.private", keyID)
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

// loadECDSAKey загружает ECDSA ключ
func (s *FileStore) loadECDSAKey(keyID string) (*KeyPair, error) {
	privateFilename := fmt.Sprintf("ecdsa_%s.private", keyID)
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

// loadEdDSAKey загружает EdDSA ключ
func (s *FileStore) loadEdDSAKey(keyID string) (*KeyPair, error) {
	privateFilename := fmt.Sprintf("eddsa_%s.private", keyID)
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

	privateKey := ed25519.PrivateKey(block.Bytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &KeyPair{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

