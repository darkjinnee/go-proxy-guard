package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"
)

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

	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм: %s", algorithm)
	}

	return &key, nil
}
