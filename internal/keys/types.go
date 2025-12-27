package keys

import (
	"crypto"
	"time"
)

// Algorithm представляет алгоритм подписи
type Algorithm string

const (
	AlgorithmHS256 Algorithm = "HS256"
	AlgorithmRS256 Algorithm = "RS256"
	AlgorithmRS512 Algorithm = "RS512"
	AlgorithmES256 Algorithm = "ES256"
	AlgorithmEdDSA Algorithm = "EdDSA"
)

// KeyStatus представляет статус ключа
type KeyStatus string

const (
	StatusActive    KeyStatus = "active"
	StatusDeprecated KeyStatus = "deprecated"
	StatusBackup    KeyStatus = "backup"
)

// KeyMetadata представляет метаданные ключа
type KeyMetadata struct {
	ID        string    `json:"id"`
	Algorithm Algorithm `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	Status    KeyStatus `json:"status"`
}

// KeyPair представляет пару ключей (для асимметричных алгоритмов)
type KeyPair struct {
	Private crypto.PrivateKey
	Public  crypto.PublicKey
}

// Key представляет ключ (для симметричных алгоритмов) или пару ключей
type Key struct {
	Metadata KeyMetadata
	HMAC     []byte   // Для HS256
	KeyPair  *KeyPair // Для RS256, RS512, ES256, EdDSA
}

// KeyStore представляет интерфейс для работы с ключами
type KeyStore interface {
	GetKey(algorithm Algorithm) (*Key, error)
	GetKeyByID(id string) (*Key, error)
	GenerateKey(algorithm Algorithm) (*Key, error)
	RegenerateKey(algorithm Algorithm) (*Key, error)
	ListKeys() ([]KeyMetadata, error)
}

