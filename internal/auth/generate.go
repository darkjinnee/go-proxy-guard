package auth

import (
	"context"
	"fmt"

	"go-proxy-guard/internal/keys"
	"go-proxy-guard/pkg/jwt"
)

// GenerateTokens генерирует пару токенов (access и refresh)
func (s *Service) GenerateTokens(
	ctx context.Context,
	req *GenerateTokenRequest,
	clientIP string,
) (*GenerateTokenResponse, error) {
	// 1. Проверка IP whitelist
	if err := checkIPWhitelist(clientIP, s.config.Token.IPWhitelist); err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeForbidden,
			Message: err.Error(),
		}
	}

	// 2. Валидация запроса
	if err := s.validateGenerateRequest(req); err != nil {
		return nil, err
	}

	// 3. Проверка алгоритма и типа
	algorithm := keys.Algorithm(req.Header.Alg)
	if !s.isAlgorithmSupported(algorithm) {
		return nil, &AuthError{
			Code:    ErrorCodeBadRequest,
			Message: fmt.Sprintf("неподдерживаемый алгоритм: %s", req.Header.Alg),
		}
	}

	if !s.isTypeSupported(req.Header.Typ) {
		return nil, &AuthError{
			Code:    ErrorCodeBadRequest,
			Message: fmt.Sprintf("неподдерживаемый тип: %s", req.Header.Typ),
		}
	}

	// 4. Подготовка claims
	// Удаляем exp из payload, если есть (время жизни берется из конфигурации)
	userClaims := make(jwt.Claims)
	for k, v := range req.Payload {
		if k != "exp" && k != "iat" && k != "type" && k != "jti" {
			userClaims[k] = v
		}
	}

	// Генерируем UUID для токенов
	jtiAccess := generateUUID()
	jtiRefresh := generateUUID()

	// 5. Генерация access_token
	accessClaims := jwt.BuildClaims(
		jwt.TokenTypeAccess,
		jtiAccess,
		userClaims,
		s.config.Token.Exp,
	)

	accessToken, err := s.jwtGen.GenerateToken(accessClaims, algorithm, s.keyStore)
	if err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeInternal,
			Message: fmt.Sprintf("ошибка генерации access_token: %v", err),
		}
	}

	// 6. Генерация refresh_token
	refreshClaims := jwt.BuildClaims(
		jwt.TokenTypeRefresh,
		jtiRefresh,
		userClaims,
		s.config.Token.RefreshExp,
	)

	refreshToken, err := s.jwtGen.GenerateToken(refreshClaims, algorithm, s.keyStore)
	if err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeInternal,
			Message: fmt.Sprintf("ошибка генерации refresh_token: %v", err),
		}
	}

	// 7. Возврат токенов
	return &GenerateTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// validateGenerateRequest валидирует запрос на генерацию токенов
func (s *Service) validateGenerateRequest(req *GenerateTokenRequest) error {
	if req.Header.Alg == "" {
		return &AuthError{
			Code:    ErrorCodeBadRequest,
			Message: "header.alg обязателен",
		}
	}

	if req.Header.Typ == "" {
		return &AuthError{
			Code:    ErrorCodeBadRequest,
			Message: "header.typ обязателен",
		}
	}

	if len(req.Payload) == 0 {
		return &AuthError{
			Code:    ErrorCodeBadRequest,
			Message: "payload не может быть пустым",
		}
	}

	return nil
}

// isAlgorithmSupported проверяет, поддерживается ли алгоритм
func (s *Service) isAlgorithmSupported(algorithm keys.Algorithm) bool {
	for _, alg := range s.config.Token.AlgSupported {
		if keys.Algorithm(alg) == algorithm {
			return true
		}
	}
	return false
}

// isTypeSupported проверяет, поддерживается ли тип
func (s *Service) isTypeSupported(typ string) bool {
	for _, t := range s.config.Token.TypSupported {
		if t == typ {
			return true
		}
	}
	return false
}
