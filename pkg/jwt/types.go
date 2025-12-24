package jwt

import (
	"go-proxy-guard/internal/keys"
)

// TokenType представляет тип токена
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

// Claims представляет claims JWT токена
type Claims map[string]interface{}

// StandardClaims представляет стандартные claims токена
type StandardClaims struct {
	Type string `json:"type"` // "access" или "refresh"
	JTI  string `json:"jti"`  // JWT ID (UUID v4)
	Exp  int64  `json:"exp"`  // Время истечения (Unix timestamp в секундах)
	IAT  int64  `json:"iat"`  // Время создания (Unix timestamp в секундах)
}

// GetType возвращает тип токена из claims
func (c Claims) GetType() string {
	if val, ok := c["type"].(string); ok {
		return val
	}
	return ""
}

// GetJTI возвращает JWT ID из claims
func (c Claims) GetJTI() string {
	if val, ok := c["jti"].(string); ok {
		return val
	}
	return ""
}

// GetExp возвращает время истечения из claims
func (c Claims) GetExp() int64 {
	if val, ok := c["exp"].(float64); ok {
		return int64(val)
	}
	if val, ok := c["exp"].(int64); ok {
		return val
	}
	return 0
}

// GetIAT возвращает время создания из claims
func (c Claims) GetIAT() int64 {
	if val, ok := c["iat"].(float64); ok {
		return int64(val)
	}
	if val, ok := c["iat"].(int64); ok {
		return val
	}
	return 0
}

// GetUserClaims возвращает пользовательские claims (исключая стандартные)
func (c Claims) GetUserClaims() Claims {
	userClaims := make(Claims)
	standardKeys := map[string]bool{
		"type": true,
		"jti":  true,
		"exp":  true,
		"iat":  true,
	}

	for k, v := range c {
		if !standardKeys[k] {
			userClaims[k] = v
		}
	}

	return userClaims
}

// Generator представляет интерфейс для генерации JWT токенов
type Generator interface {
	GenerateToken(claims Claims, algorithm keys.Algorithm, keyStore keys.KeyStore, kid string) (string, error)
}

// Validator представляет интерфейс для валидации JWT токенов
type Validator interface {
	ValidateToken(token string, algorithm keys.Algorithm, keyStore keys.KeyStore) (Claims, error)
	ValidateTokenType(token string, expectedType TokenType, algorithm keys.Algorithm, keyStore keys.KeyStore) (Claims, error)
}
