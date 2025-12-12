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
func (g *generator) GenerateToken(claims Claims, algorithm keys.Algorithm, keyStore keys.KeyStore) (string, error) {
	// Получаем ключ из хранилища
	key, err := keyStore.GetKey(algorithm)
	if err != nil {
		return "", fmt.Errorf("ошибка получения ключа: %w", err)
	}

	// Преобразуем claims в jwt.MapClaims
	jwtClaims := jwt.MapClaims{}
	for k, v := range claims {
		jwtClaims[k] = v
	}

	// Создаем токен
	token := jwt.NewWithClaims(g.getSigningMethod(algorithm), jwtClaims)

	// Получаем ключ для подписи
	signingKey, err := g.getSigningKey(key, algorithm)
	if err != nil {
		return "", fmt.Errorf("ошибка получения ключа для подписи: %w", err)
	}

	// Подписываем токен
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("ошибка подписи токена: %w", err)
	}

	return tokenString, nil
}

// getSigningMethod возвращает метод подписи для алгоритма
func (g *generator) getSigningMethod(algorithm keys.Algorithm) jwt.SigningMethod {
	switch algorithm {
	case keys.AlgorithmHS256:
		return jwt.SigningMethodHS256
	case keys.AlgorithmRS256:
		return jwt.SigningMethodRS256
	case keys.AlgorithmRS512:
		return jwt.SigningMethodRS512
	case keys.AlgorithmES256:
		return jwt.SigningMethodES256
	case keys.AlgorithmEdDSA:
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodHS256
	}
}

// getSigningKey возвращает ключ для подписи в зависимости от алгоритма
func (g *generator) getSigningKey(key *keys.Key, algorithm keys.Algorithm) (interface{}, error) {
	switch algorithm {
	case keys.AlgorithmHS256:
		if key.HMAC == nil {
			return nil, fmt.Errorf("HMAC ключ не найден")
		}
		return key.HMAC, nil

	case keys.AlgorithmRS256, keys.AlgorithmRS512:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("RSA ключ не найден")
		}
		rsaKey, ok := key.KeyPair.Private.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("неверный тип ключа для RSA")
		}
		return rsaKey, nil

	case keys.AlgorithmES256:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("ECDSA ключ не найден")
		}
		ecdsaKey, ok := key.KeyPair.Private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("неверный тип ключа для ECDSA")
		}
		return ecdsaKey, nil

	case keys.AlgorithmEdDSA:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("EdDSA ключ не найден")
		}
		ed25519Key, ok := key.KeyPair.Private.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("неверный тип ключа для EdDSA")
		}
		return ed25519Key, nil

	default:
		return nil, fmt.Errorf("неподдерживаемый алгоритм: %s", algorithm)
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
