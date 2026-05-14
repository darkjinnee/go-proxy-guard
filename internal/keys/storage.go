package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// saveKey сохраняет ключ в файл с шифрованием
func (s *FileStore) saveKey(key *Key) error {
	switch key.Metadata.Algorithm {
	case AlgorithmHS256, AlgorithmHS512:
		return s.saveHMACKey(key)
	case AlgorithmRS256, AlgorithmRS512:
		return s.saveRSAKey(key)
	case AlgorithmES256, AlgorithmES512:
		return s.saveECDSAKey(key)
	case AlgorithmEdDSA:
		return s.saveEdDSAKey(key)
	default:
		return fmt.Errorf("неподдерживаемый алгоритм: %s", key.Metadata.Algorithm)
	}
}

// saveHMACKey сохраняет HMAC ключ
func (s *FileStore) saveHMACKey(key *Key) error {
	// Шифруем ключ
	encrypted, err := encryptData(key.HMAC, s.masterKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования ключа: %w", err)
	}

	// Кодируем в base64
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	prefix, err := hsNamePrefix(key.Metadata.Algorithm)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s%s.key", prefix, key.Metadata.ID)
	path := filepath.Join(s.keysDir, filename)

	if err := os.WriteFile(path, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("ошибка записи файла: %w", err)
	}

	return nil
}

// saveRSAKey сохраняет RSA ключ
func (s *FileStore) saveRSAKey(key *Key) error {
	rsaKey, ok := key.KeyPair.Private.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("неверный тип ключа для RSA")
	}

	// Сохраняем приватный ключ
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Шифруем приватный ключ
	encryptedPrivate, err := encryptData(privateKeyPEM, s.masterKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования приватного ключа: %w", err)
	}

	prefix, err := rsaNamePrefix(key.Metadata.Algorithm)
	if err != nil {
		return err
	}

	privateFilename := fmt.Sprintf("%s%s.private", prefix, key.Metadata.ID)
	privatePath := filepath.Join(s.keysDir, privateFilename)
	if err := os.WriteFile(privatePath, encryptedPrivate, 0600); err != nil {
		return fmt.Errorf("ошибка записи приватного ключа: %w", err)
	}

	// Сохраняем публичный ключ
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		return fmt.Errorf("ошибка маршалинга публичного ключа: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Шифруем публичный ключ
	encryptedPublic, err := encryptData(publicKeyPEM, s.masterKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования публичного ключа: %w", err)
	}

	publicFilename := fmt.Sprintf("%s%s.public", prefix, key.Metadata.ID)
	publicPath := filepath.Join(s.keysDir, publicFilename)
	if err := os.WriteFile(publicPath, encryptedPublic, 0600); err != nil {
		return fmt.Errorf("ошибка записи публичного ключа: %w", err)
	}

	return nil
}

// saveECDSAKey сохраняет ECDSA ключ
func (s *FileStore) saveECDSAKey(key *Key) error {
	ecdsaKey, ok := key.KeyPair.Private.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("неверный тип ключа для ECDSA")
	}

	// Сохраняем приватный ключ
	privateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaKey)
	if err != nil {
		return fmt.Errorf("ошибка маршалинга приватного ключа: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Шифруем приватный ключ
	encryptedPrivate, err := encryptData(privateKeyPEM, s.masterKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования приватного ключа: %w", err)
	}

	prefix, err := esNamePrefix(key.Metadata.Algorithm)
	if err != nil {
		return err
	}

	privateFilename := fmt.Sprintf("%s%s.private", prefix, key.Metadata.ID)
	privatePath := filepath.Join(s.keysDir, privateFilename)
	if err := os.WriteFile(privatePath, encryptedPrivate, 0600); err != nil {
		return fmt.Errorf("ошибка записи приватного ключа: %w", err)
	}

	// Сохраняем публичный ключ
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(ecdsaKey.Public())
	if err != nil {
		return fmt.Errorf("ошибка маршалинга публичного ключа: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Шифруем публичный ключ
	encryptedPublic, err := encryptData(publicKeyPEM, s.masterKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования публичного ключа: %w", err)
	}

	publicFilename := fmt.Sprintf("%s%s.public", prefix, key.Metadata.ID)
	publicPath := filepath.Join(s.keysDir, publicFilename)
	if err := os.WriteFile(publicPath, encryptedPublic, 0600); err != nil {
		return fmt.Errorf("ошибка записи публичного ключа: %w", err)
	}

	return nil
}

// saveEdDSAKey сохраняет EdDSA ключ
func (s *FileStore) saveEdDSAKey(key *Key) error {
	ed25519Key, ok := key.KeyPair.Private.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("неверный тип ключа для EdDSA")
	}

	// Сохраняем приватный ключ
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ed25519Key,
	})

	// Шифруем приватный ключ
	encryptedPrivate, err := encryptData(privateKeyPEM, s.masterKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования приватного ключа: %w", err)
	}

	privateFilename := fmt.Sprintf("eddsa_%s.private", key.Metadata.ID)
	privatePath := filepath.Join(s.keysDir, privateFilename)
	if err := os.WriteFile(privatePath, encryptedPrivate, 0600); err != nil {
		return fmt.Errorf("ошибка записи приватного ключа: %w", err)
	}

	// Сохраняем публичный ключ
	publicKeyBytes, ok := key.KeyPair.Public.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("неверный тип публичного ключа для EdDSA")
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Шифруем публичный ключ
	encryptedPublic, err := encryptData(publicKeyPEM, s.masterKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования публичного ключа: %w", err)
	}

	publicFilename := fmt.Sprintf("eddsa_%s.public", key.Metadata.ID)
	publicPath := filepath.Join(s.keysDir, publicFilename)
	if err := os.WriteFile(publicPath, encryptedPublic, 0600); err != nil {
		return fmt.Errorf("ошибка записи публичного ключа: %w", err)
	}

	return nil
}

// backupKey создает резервную копию ключа
func (s *FileStore) backupKey(key *Key) error {
	// Определяем имена файлов в зависимости от алгоритма
	var files []string

	switch key.Metadata.Algorithm {
	case AlgorithmHS256, AlgorithmHS512:
		prefix, err := hsNamePrefix(key.Metadata.Algorithm)
		if err != nil {
			return err
		}
		files = []string{fmt.Sprintf("%s%s.key", prefix, key.Metadata.ID)}
	case AlgorithmRS256, AlgorithmRS512:
		prefix, err := rsaNamePrefix(key.Metadata.Algorithm)
		if err != nil {
			return err
		}
		files = []string{
			fmt.Sprintf("%s%s.private", prefix, key.Metadata.ID),
			fmt.Sprintf("%s%s.public", prefix, key.Metadata.ID),
		}
	case AlgorithmES256, AlgorithmES512:
		prefix, err := esNamePrefix(key.Metadata.Algorithm)
		if err != nil {
			return err
		}
		files = []string{
			fmt.Sprintf("%s%s.private", prefix, key.Metadata.ID),
			fmt.Sprintf("%s%s.public", prefix, key.Metadata.ID),
		}
	case AlgorithmEdDSA:
		files = []string{
			fmt.Sprintf("eddsa_%s.private", key.Metadata.ID),
			fmt.Sprintf("eddsa_%s.public", key.Metadata.ID),
		}
	}

	// Копируем файлы с добавлением суффикса .backup
	for _, filename := range files {
		srcPath := filepath.Join(s.keysDir, filename)
		dstPath := srcPath + ".backup"

		data, err := os.ReadFile(srcPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Файл не существует, пропускаем
			}
			return fmt.Errorf("ошибка чтения файла %s: %w", filename, err)
		}

		if err := os.WriteFile(dstPath, data, 0600); err != nil {
			return fmt.Errorf("ошибка записи резервной копии %s: %w", filename, err)
		}
	}

	return nil
}
