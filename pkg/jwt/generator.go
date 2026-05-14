package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"go-proxy-guard/internal/keys"
)

// generator реализует интерфейс Generator
type generator struct{}

// NewGenerator создает новый генератор JWT токенов
func NewGenerator() Generator {
	return &generator{}
}

// GenerateToken генерирует JWT токен с указанными claims
func (g *generator) GenerateToken(claims Claims, algorithm keys.Algorithm, keyStore keys.KeyStore, kid string) (string, error) {
	// Получаем ключ из хранилища
	key, err := keyStore.GetKey(algorithm)
	if err != nil {
		return "", fmt.Errorf("error getting key: %w", err)
	}

	// Преобразуем claims в jwt.MapClaims
	jwtClaims := jwt.MapClaims{}
	for k, v := range claims {
		jwtClaims[k] = v
	}

	// Создаем токен
	token := jwt.NewWithClaims(g.getSigningMethod(algorithm), jwtClaims)

	// Добавляем kid в заголовок, если указан, иначе используем ID ключа
	if kid != "" {
		token.Header["kid"] = kid
	} else {
		// Используем ID ключа из метаданных
		token.Header["kid"] = key.Metadata.ID
	}

	// Получаем ключ для подписи
	signingKey, err := g.getSigningKey(key, algorithm)
	if err != nil {
		return "", fmt.Errorf("error getting signing key: %w", err)
	}

	// Подписываем токен
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return tokenString, nil
}

// getSigningMethod возвращает метод подписи для алгоритма
func (g *generator) getSigningMethod(algorithm keys.Algorithm) jwt.SigningMethod {
	switch algorithm {
	case keys.AlgorithmHS256:
		return jwt.SigningMethodHS256
	case keys.AlgorithmHS512:
		return jwt.SigningMethodHS512
	case keys.AlgorithmRS256:
		return jwt.SigningMethodRS256
	case keys.AlgorithmRS512:
		return jwt.SigningMethodRS512
	case keys.AlgorithmES256:
		return jwt.SigningMethodES256
	case keys.AlgorithmES512:
		return jwt.SigningMethodES512
	case keys.AlgorithmEdDSA:
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodHS256
	}
}

// getSigningKey возвращает ключ для подписи в зависимости от алгоритма
func (g *generator) getSigningKey(key *keys.Key, algorithm keys.Algorithm) (interface{}, error) {
	switch algorithm {
	case keys.AlgorithmHS256, keys.AlgorithmHS512:
		if key.HMAC == nil {
			return nil, fmt.Errorf("HMAC key not found")
		}
		return key.HMAC, nil

	case keys.AlgorithmRS256, keys.AlgorithmRS512:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("RSA key not found")
		}
		rsaKey, ok := key.KeyPair.Private.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid key type for RSA")
		}
		return rsaKey, nil

	case keys.AlgorithmES256, keys.AlgorithmES512:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("ECDSA key not found")
		}
		ecdsaKey, ok := key.KeyPair.Private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid key type for ECDSA")
		}
		return ecdsaKey, nil

	case keys.AlgorithmEdDSA:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("EdDSA key not found")
		}
		ed25519Key, ok := key.KeyPair.Private.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid key type for EdDSA")
		}
		return ed25519Key, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// BuildClaims создает claims для токена
func BuildClaims(tokenType TokenType, jti string, userClaims Claims, expMinutes int) Claims {
	now := time.Now().Unix()
	exp := now + int64(expMinutes*60)

	claims := make(Claims)

	// Стандартные claims
	claims["type"] = string(tokenType)
	claims["jti"] = jti
	claims["exp"] = exp
	claims["iat"] = now

	// Пользовательские claims
	for k, v := range userClaims {
		claims[k] = v
	}

	return claims
}
