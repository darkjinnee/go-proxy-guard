package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go-proxy-guard/internal/config"
	"go-proxy-guard/internal/keys"
	"go-proxy-guard/pkg/jwt"
)

// ProxyRequest выполняет проксирование HTTP запроса
func (s *Service) ProxyRequest(ctx context.Context, req *ProxyRequest) (*ProxyResponse, error) {
	// 1. Валидация Host header
	if req.Host == "" {
		return nil, &ProxyError{
			Code:    http.StatusBadRequest,
			Message: "Host header is required",
		}
	}

	// Нормализация домена
	domain := normalizeDomain(req.Host)

	// 2. Проверка домена в конфигурации
	_, err := s.proxyConfig.GetDomainConfig(domain)
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusNotFound,
			Message: fmt.Sprintf("Domain not configured: %s", domain),
		}
	}

	// Извлекаем IP клиента
	clientIP := extractClientIP(req.RemoteAddr, req.XForwardedFor, req.XRealIP)

	// 3. Извлечение токена
	token, err := extractTokenFromHeader(req.Headers["Authorization"])
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusUnauthorized,
			Message: fmt.Sprintf("Ошибка извлечения токена: %v", err),
		}
	}

	// 4. Проверка размера токена
	if len(token) > s.appConfig.Token.MaxJWTSizeBytes {
		return nil, &ProxyError{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Размер JWT токена превышает максимальный (%d байт)", s.appConfig.Token.MaxJWTSizeBytes),
		}
	}

	// 5. Валидация токена
	algorithm, err := extractAlgorithmFromToken(token)
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusUnauthorized,
			Message: fmt.Sprintf("Ошибка определения алгоритма: %v", err),
		}
	}

	claims, err := s.jwtVal.ValidateTokenType(token, jwt.TokenTypeAccess, algorithm, s.keyStore)
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusUnauthorized,
			Message: fmt.Sprintf("Токен невалиден: %v", err),
		}
	}

	// 6. Извлечение claims
	userClaims := claims.GetUserClaims()

	// 7. Маршрутизация
	route, err := s.findRoute(domain, req.Path, req.Method, clientIP)
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusNotFound,
			Message: err.Error(),
		}
	}

	// 8. Переписывание пути
	targetPath, err := rewritePath(req.Path, route.Match.Path, getRewritePath(route))
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusInternalServerError,
			Message: fmt.Sprintf("Ошибка переписывания пути: %v", err),
		}
	}

	// 9. Проксирование запроса
	return s.doProxy(ctx, route, req, targetPath, userClaims)
}

// doProxy выполняет HTTP запрос к целевому сервису
func (s *Service) doProxy(
	ctx context.Context,
	route *config.Route,
	req *ProxyRequest,
	targetPath string,
	userClaims jwt.Claims,
) (*ProxyResponse, error) {
	// Формируем URL целевого сервиса
	targetURL, err := url.Parse(route.ForwardTo.URL)
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusInternalServerError,
			Message: fmt.Sprintf("Ошибка парсинга URL: %v", err),
		}
	}

	// Парсим путь с query параметрами
	parsedPath, err := url.Parse(targetPath)
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusInternalServerError,
			Message: fmt.Sprintf("Ошибка парсинга пути: %v", err),
		}
	}

	targetURL.Path = parsedPath.Path
	targetURL.RawQuery = parsedPath.RawQuery

	// Определяем таймаут
	timeout := time.Duration(s.appConfig.Proxy.TimeoutMS) * time.Millisecond
	if route.ForwardTo.TimeoutMS != nil {
		timeout = time.Duration(*route.ForwardTo.TimeoutMS) * time.Millisecond
	}

	// Создаем контекст с таймаутом
	proxyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Создаем HTTP запрос
	httpReq, err := http.NewRequestWithContext(proxyCtx, req.Method, targetURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusInternalServerError,
			Message: fmt.Sprintf("Ошибка создания запроса: %v", err),
		}
	}

	// Копируем заголовки из исходного запроса
	for k, v := range req.Headers {
		// Пропускаем некоторые заголовки
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Connection") {
			continue
		}
		httpReq.Header.Set(k, v)
	}

	// Устанавливаем Host header (если указан host_override)
	if route.Match.HostOverride != nil && *route.Match.HostOverride != "" {
		httpReq.Host = *route.Match.HostOverride
	}

	// Добавляем заголовки из default_headers
	for k, v := range s.appConfig.Proxy.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}

	// Добавляем заголовки из route.add_headers
	for k, v := range route.ForwardTo.AddHeaders {
		httpReq.Header.Set(k, v)
	}

	// Добавляем X-JWT-* заголовки из claims
	for k, v := range userClaims {
		headerName := fmt.Sprintf("X-JWT-%s", strings.ReplaceAll(k, "_", "-"))
		httpReq.Header.Set(headerName, fmt.Sprintf("%v", v))
	}

	// Выполняем запрос
	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		if err == context.DeadlineExceeded {
			return nil, &ProxyError{
				Code:    http.StatusGatewayTimeout,
				Message: "Таймаут ожидания ответа от целевого сервиса",
			}
		}
		return nil, &ProxyError{
			Code:    http.StatusBadGateway,
			Message: fmt.Sprintf("Ошибка подключения к целевому сервису: %v", err),
		}
	}
	defer resp.Body.Close()

	// Читаем тело ответа
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &ProxyError{
			Code:    http.StatusInternalServerError,
			Message: fmt.Sprintf("Ошибка чтения ответа: %v", err),
		}
	}

	// Формируем ответ
	responseHeaders := make(map[string][]string)
	for k, v := range resp.Header {
		responseHeaders[k] = v
	}

	return &ProxyResponse{
		StatusCode: resp.StatusCode,
		Headers:    responseHeaders,
		Body:       body,
	}, nil
}

// getRewritePath возвращает rewrite_path из маршрута
func getRewritePath(route *config.Route) string {
	if route.ForwardTo.RewritePath != nil {
		return *route.ForwardTo.RewritePath
	}
	return ""
}

// normalizeDomain нормализует домен
func normalizeDomain(host string) string {
	// Удаление порта
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Приведение к нижнему регистру
	return strings.ToLower(strings.TrimSpace(host))
}

// extractTokenFromHeader извлекает токен из заголовка Authorization
func extractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", fmt.Errorf("заголовок Authorization отсутствует")
	}

	// Формат: "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("неверный формат заголовка Authorization")
	}

	return parts[1], nil
}

// extractAlgorithmFromToken извлекает алгоритм из токена (копия из auth/utils.go)
func extractAlgorithmFromToken(tokenString string) (keys.Algorithm, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("неверный формат токена")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("ошибка декодирования header: %w", err)
	}

	headerStr := string(headerBytes)
	if !strings.Contains(headerStr, `"alg"`) {
		return "", fmt.Errorf("header не содержит alg")
	}

	algStart := strings.Index(headerStr, `"alg"`)
	if algStart == -1 {
		return "", fmt.Errorf("не найден alg в header")
	}

	valueStart := strings.Index(headerStr[algStart:], `:`)
	if valueStart == -1 {
		return "", fmt.Errorf("неверный формат alg в header")
	}

	valueStart += algStart + 1
	for valueStart < len(headerStr) && (headerStr[valueStart] == ' ' || headerStr[valueStart] == '"') {
		valueStart++
	}

	valueEnd := valueStart
	for valueEnd < len(headerStr) && headerStr[valueEnd] != '"' && headerStr[valueEnd] != ',' && headerStr[valueEnd] != '}' {
		valueEnd++
	}

	alg := headerStr[valueStart:valueEnd]
	return keys.Algorithm(alg), nil
}
