package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"
)

// generateHMACKey генерирует случайный секрет заданной длины (байты), например 32 для HS256, 64 для HS512.
func generateHMACKey(secretBytes int) ([]byte, error) {
	if secretBytes <= 0 {
		return nil, fmt.Errorf("длина секрета HMAC должна быть больше 0")
	}
	key := make([]byte, secretBytes)
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

// generateECDSAKey генерирует пару ECDSA на указанной кривой (например elliptic.P256() для ES256, elliptic.P521() для ES512).
func generateECDSAKey(curve elliptic.Curve) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
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
		hmacKey, err := generateHMACKey(32)
		if err != nil {
			return nil, err
		}
		key.HMAC = hmacKey

	case AlgorithmHS512:
		hmacKey, err := generateHMACKey(64)
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
		keyPair, err := generateECDSAKey(elliptic.P256())
		if err != nil {
			return nil, err
		}
		key.KeyPair = keyPair

	case AlgorithmES512:
		keyPair, err := generateECDSAKey(elliptic.P521())
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
