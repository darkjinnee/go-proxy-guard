package auth

import (
	"context"
	"fmt"

	"go-proxy-guard/internal/keys"
	"go-proxy-guard/pkg/jwt"
)

// RefreshTokens обновляет пару токенов на основе refresh_token
func (s *Service) RefreshTokens(
	ctx context.Context,
	req *RefreshTokenRequest,
	clientIP string,
) (*RefreshTokenResponse, error) {
	// 1. Проверка IP whitelist
	if err := checkIPWhitelist(clientIP, s.config.Token.IPWhitelist); err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeForbidden,
			Message: err.Error(),
		}
	}

	// 2. Валидация запроса
	if req.RefreshToken == "" {
		return nil, &AuthError{
			Code:    ErrorCodeBadRequest,
			Message: "refresh_token обязателен",
		}
	}

	// 3. Проверка размера токена
	if len(req.RefreshToken) > s.config.Token.MaxJWTSizeBytes {
		return nil, &AuthError{
			Code:    ErrorCodeBadRequest,
			Message: fmt.Sprintf("размер refresh_token превышает максимальный (%d байт)", s.config.Token.MaxJWTSizeBytes),
		}
	}

	// 4. Парсим токен без валидации для извлечения алгоритма
	unverifiedClaims, err := jwt.ParseTokenWithoutValidation(req.RefreshToken)
	if err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeUnauthorized,
			Message: fmt.Sprintf("неверный формат токена: %v", err),
		}
	}

	// Проверяем наличие jti
	jti := unverifiedClaims.GetJTI()
	if jti == "" {
		return nil, &AuthError{
			Code:    ErrorCodeUnauthorized,
			Message: "токен невалиден: отсутствует jti",
		}
	}

	// Определяем алгоритм из header токена
	// Для этого нужно декодировать header
	var algorithm keys.Algorithm
	algorithm, err = extractAlgorithmFromToken(req.RefreshToken)
	if err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeUnauthorized,
			Message: fmt.Sprintf("ошибка определения алгоритма: %v", err),
		}
	}

	// 5. Валидация refresh_token
	claims, err := s.jwtVal.ValidateTokenType(
		req.RefreshToken,
		jwt.TokenTypeRefresh,
		algorithm,
		s.keyStore,
	)
	if err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeUnauthorized,
			Message: fmt.Sprintf("токен невалиден: %v", err),
		}
	}

	// 6. Проверка использования токена в Redis
	used, err := s.redis.IsTokenUsed(ctx, jti)
	if err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeInternal,
			Message: fmt.Sprintf("ошибка проверки токена в Redis: %v", err),
		}
	}

	if used {
		return nil, &AuthError{
			Code:    ErrorCodeUnauthorized,
			Message: "refresh_token уже использован",
		}
	}

	// 7. Извлечение данных пользователя
	userClaims := claims.GetUserClaims()

	// 8. Генерация новых токенов
	jtiAccess := generateUUID()
	jtiRefresh := generateUUID()

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

	// 9. Помечение старого токена как использованного
	ttlSeconds := s.config.Token.RefreshExp * 60 // Конвертация минут в секунды
	if err := s.redis.MarkTokenAsUsed(ctx, jti, ttlSeconds); err != nil {
		return nil, &AuthError{
			Code:    ErrorCodeInternal,
			Message: fmt.Sprintf("ошибка сохранения токена в Redis: %v", err),
		}
	}

	// 10. Возврат новых токенов
	return &RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
