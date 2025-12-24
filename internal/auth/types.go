package auth

import (
	"go-proxy-guard/internal/config"
	"go-proxy-guard/internal/keys"
	"go-proxy-guard/internal/redis"
	"go-proxy-guard/pkg/jwt"
)

// Service представляет сервис аутентификации
type Service struct {
	config   *config.AppConfig
	keyStore keys.KeyStore
	redis    *redis.Client
	jwtGen   jwt.Generator
	jwtVal   jwt.Validator
}

// NewService создает новый сервис аутентификации
func NewService(
	cfg *config.AppConfig,
	keyStore keys.KeyStore,
	redisClient *redis.Client,
) *Service {
	return &Service{
		config:   cfg,
		keyStore: keyStore,
		redis:    redisClient,
		jwtGen:   jwt.NewGenerator(),
		jwtVal:   jwt.NewValidator(),
	}
}

// GenerateTokenRequest представляет запрос на генерацию токенов
type GenerateTokenRequest struct {
	Header  TokenHeader `json:"header"`
	Payload jwt.Claims  `json:"payload"`
}

// TokenHeader представляет заголовок токена
type TokenHeader struct {
	Alg string `json:"alg"` // Алгоритм подписи
	Typ string `json:"typ"` // Тип токена
	Kid string `json:"kid,omitempty"` // Key ID (опционально)
}

// GenerateTokenResponse представляет ответ на генерацию токенов
type GenerateTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenRequest представляет запрос на обновление токенов
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse представляет ответ на обновление токенов
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
