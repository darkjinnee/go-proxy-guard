package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// encryptData шифрует данные с использованием AES-256-GCM
func encryptData(data []byte, masterKey []byte) ([]byte, error) {
	// Создаем ключ из мастер-ключа через SHA-256
	key := sha256.Sum256(masterKey)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("ошибка создания cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Генерируем nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ошибка генерации nonce: %w", err)
	}

	// Шифруем данные
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptData расшифровывает данные с использованием AES-256-GCM
func decryptData(encryptedData []byte, masterKey []byte) ([]byte, error) {
	// Создаем ключ из мастер-ключа через SHA-256
	key := sha256.Sum256(masterKey)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("ошибка создания cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %w", err)
	}

	// Извлекаем nonce
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("недостаточная длина зашифрованных данных")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Расшифровываем данные
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	return plaintext, nil
}

