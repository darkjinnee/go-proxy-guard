package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"go-proxy-guard/internal/keys"
)

// validator реализует интерфейс Validator
type validator struct{}

// NewValidator создает новый валидатор JWT токенов
func NewValidator() Validator {
	return &validator{}
}

// ValidateToken валидирует JWT токен и возвращает claims
func (v *validator) ValidateToken(token string, algorithm keys.Algorithm, keyStore keys.KeyStore) (Claims, error) {
	// Получаем ключ из хранилища
	key, err := keyStore.GetKey(algorithm)
	if err != nil {
		return nil, fmt.Errorf("error getting key: %w", err)
	}

	expectedMethod, err := v.getSigningMethod(algorithm)
	if err != nil {
		return nil, err
	}

	// Парсим токен
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Проверяем алгоритм
		if token.Method != expectedMethod {
			return nil, fmt.Errorf("invalid signing algorithm: %v", token.Method.Alg())
		}

		// Получаем ключ для проверки подписи
		return v.getVerificationKey(key, algorithm)
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// Извлекаем claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Проверяем время истечения
	if err := v.validateExpiration(claims); err != nil {
		return nil, err
	}

	// Преобразуем в наш формат Claims
	result := make(Claims)
	for k, v := range claims {
		result[k] = v
	}

	return result, nil
}

// ValidateTokenType валидирует JWT токен и проверяет его тип
func (v *validator) ValidateTokenType(token string, expectedType TokenType, algorithm keys.Algorithm, keyStore keys.KeyStore) (Claims, error) {
	claims, err := v.ValidateToken(token, algorithm, keyStore)
	if err != nil {
		return nil, err
	}

	// Проверяем тип токена
	tokenType := claims.GetType()
	if tokenType != string(expectedType) {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", expectedType, tokenType)
	}

	return claims, nil
}

// getSigningMethod возвращает метод подписи для алгоритма
func (v *validator) getSigningMethod(algorithm keys.Algorithm) (jwt.SigningMethod, error) {
	switch algorithm {
	case keys.AlgorithmRS256:
		return jwt.SigningMethodRS256, nil
	case keys.AlgorithmRS512:
		return jwt.SigningMethodRS512, nil
	case keys.AlgorithmES256:
		return jwt.SigningMethodES256, nil
	case keys.AlgorithmES512:
		return jwt.SigningMethodES512, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// getVerificationKey возвращает ключ для проверки подписи
func (v *validator) getVerificationKey(key *keys.Key, algorithm keys.Algorithm) (interface{}, error) {
	switch algorithm {
	case keys.AlgorithmRS256, keys.AlgorithmRS512:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("RSA key not found")
		}
		rsaKey, ok := key.KeyPair.Public.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type for RSA")
		}
		return rsaKey, nil

	case keys.AlgorithmES256, keys.AlgorithmES512:
		if key.KeyPair == nil {
			return nil, fmt.Errorf("ECDSA key not found")
		}
		ecdsaKey, ok := key.KeyPair.Public.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid public key type for ECDSA")
		}
		return ecdsaKey, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// validateExpiration проверяет время истечения токена
func (v *validator) validateExpiration(claims jwt.MapClaims) error {
	exp, ok := claims["exp"]
	if !ok {
		return fmt.Errorf("claim 'exp' is missing")
	}

	var expTime int64
	switch val := exp.(type) {
	case float64:
		expTime = int64(val)
	case int64:
		expTime = val
	case int:
		expTime = int64(val)
	default:
		return fmt.Errorf("invalid format for claim 'exp'")
	}

	// Проверяем, не истек ли токен
	now := time.Now().Unix()
	if expTime <= now {
		return fmt.Errorf("token has expired")
	}

	return nil
}

// ParseTokenWithoutValidation парсит токен без валидации подписи (только для извлечения claims)
func ParseTokenWithoutValidation(tokenString string) (Claims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	result := make(Claims)
	for k, v := range claims {
		result[k] = v
	}

	return result, nil
}
