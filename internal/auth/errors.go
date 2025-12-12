package auth

import "fmt"

// ErrorCode представляет код ошибки аутентификации
type ErrorCode int

const (
	ErrorCodeBadRequest   ErrorCode = 400
	ErrorCodeUnauthorized ErrorCode = 401
	ErrorCodeForbidden    ErrorCode = 403
	ErrorCodeInternal     ErrorCode = 500
)

// AuthError представляет ошибку аутентификации
type AuthError struct {
	Code    ErrorCode
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("auth error [%d]: %s", e.Code, e.Message)
}

// HTTPStatus возвращает HTTP статус код для ошибки
func (e *AuthError) HTTPStatus() int {
	return int(e.Code)
}
