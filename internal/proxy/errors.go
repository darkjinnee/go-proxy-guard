package proxy

import "fmt"

// ProxyError представляет ошибку проксирования
type ProxyError struct {
	Code    int
	Message string
}

func (e *ProxyError) Error() string {
	return fmt.Sprintf("proxy error [%d]: %s", e.Code, e.Message)
}

// HTTPStatus возвращает HTTP статус код для ошибки
func (e *ProxyError) HTTPStatus() int {
	return e.Code
}
