package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"
)

// generateHMACKey генерирует ключ для HMAC (HS256)
func generateHMACKey() ([]byte, error) {
	// Генерируем 256-битный ключ (32 байта)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("ошибка генерации HMAC ключа: %w", err)
	}
	return key, nil
}

// generateRSAKey генерирует пару ключей RSA
func generateRSAKey(bits int) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации RSA ключа: %w", err)
	}

	return &KeyPair{
		Private: privateKey,
		Public:  privateKey.Public(),
	}, nil
}

// generateECDSAKey генерирует пару ключей ECDSA
func generateECDSAKey() (*KeyPair, error) {
	// Используем кривую P-256 для ES256
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации ECDSA ключа: %w", err)
	}

	return &KeyPair{
		Private: privateKey,
		Public:  privateKey.Public(),
	}, nil
}

// generateEdDSAKey генерирует пару ключей EdDSA (Ed25519)
func generateEdDSAKey() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации EdDSA ключа: %w", err)
	}

	return &KeyPair{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

// GenerateKey генерирует ключ для указанного алгоритма
func GenerateKey(algorithm Algorithm) (*Key, error) {
	metadata := KeyMetadata{
		ID:        generateUUID(),
		Algorithm: algorithm,
		CreatedAt: time.Now(),
		Status:    StatusActive,
	}

	var key Key
	key.Metadata = metadata

	switch algorithm {
	case AlgorithmHS256:
		hmacKey, err := generateHMACKey()
		if err != nil {
			return nil, err
		}
		key.HMAC = hmacKey

	case AlgorithmRS256:
		keyPair, err := generateRSAKey(2048) // 2048 бит для RS256
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	case AlgorithmRS512:
		keyPair, err := generateRSAKey(4096) // 4096 бит для RS512
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	case AlgorithmES256:
		keyPair, err := generateECDSAKey()
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	case AlgorithmEdDSA:
		keyPair, err := generateEdDSAKey()
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм: %s", algorithm)
	}

	return &key, nil
}

