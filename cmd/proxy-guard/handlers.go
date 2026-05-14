package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"go-proxy-guard/internal/auth"
	"go-proxy-guard/internal/clientip"
	"go-proxy-guard/internal/config"
	"go-proxy-guard/internal/logger"
	"go-proxy-guard/internal/proxy"
)

var errRequestEntityTooLarge = errors.New("request entity too large")

// readRequestBodyLimited читает r.Body целиком, если размер не превышает maxBodySizeMB.
// При превышении возвращает errRequestEntityTooLarge и освобождает остаток тела.
func readRequestBodyLimited(r *http.Request, maxBodySizeMB int) ([]byte, error) {
	maxBytes := int64(maxBodySizeMB) * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		_, _ = io.Copy(io.Discard, r.Body)
		return nil, errRequestEntityTooLarge
	}
	return body, nil
}

// handleGenerateTokens обрабатывает запрос на генерацию токенов
func handleGenerateTokens(
	authService *auth.Service,
	log logger.Logger,
	cfg *config.AppConfig,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		// Извлекаем IP клиента
		clientIP := clientip.ClientIP(
			r.RemoteAddr,
			r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Real-IP"),
		)

		body, err := readRequestBodyLimited(r, cfg.Proxy.MaxBodySizeMB)
		if errors.Is(err, errRequestEntityTooLarge) {
			log.Warn("Request body too large", logger.NewField("path", r.URL.Path))
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			log.Error("Error reading request body", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Парсим JSON
		var req auth.GenerateTokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Warn("Error parsing JSON", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Генерируем токены
		resp, err := authService.GenerateTokens(r.Context(), &req, clientIP)
		if err != nil {
			handleAuthError(w, err, log)
			return
		}

		// Возвращаем ответ
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Error("Error encoding response", logger.NewField("error", err.Error()))
		}
	}
}

// handleRefreshTokens обрабатывает запрос на обновление токенов
func handleRefreshTokens(
	authService *auth.Service,
	log logger.Logger,
	cfg *config.AppConfig,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		// Извлекаем IP клиента
		clientIP := clientip.ClientIP(
			r.RemoteAddr,
			r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Real-IP"),
		)

		body, err := readRequestBodyLimited(r, cfg.Proxy.MaxBodySizeMB)
		if errors.Is(err, errRequestEntityTooLarge) {
			log.Warn("Request body too large", logger.NewField("path", r.URL.Path))
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			log.Error("Error reading request body", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Парсим JSON
		var req auth.RefreshTokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Warn("Error parsing JSON", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Обновляем токены
		resp, err := authService.RefreshTokens(r.Context(), &req, clientIP)
		if err != nil {
			handleAuthError(w, err, log)
			return
		}

		// Возвращаем ответ
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Error("Error encoding response", logger.NewField("error", err.Error()))
		}
	}
}

// handleProxy обрабатывает проксирование запросов
func handleProxy(proxyService *proxy.Service, log logger.Logger, cfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		body, err := readRequestBodyLimited(r, cfg.Proxy.MaxBodySizeMB)
		if errors.Is(err, errRequestEntityTooLarge) {
			log.Warn("Request body too large", logger.NewField("path", r.URL.Path))
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			log.Error("Error reading request body", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Формируем заголовки
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		// Формируем путь с query параметрами
		path := r.URL.Path
		if r.URL.RawQuery != "" {
			path = path + "?" + r.URL.RawQuery
		}

		// Создаем запрос для проксирования
		proxyReq := &proxy.ProxyRequest{
			Method:        r.Method,
			Path:          path,
			Host:          r.Host,
			Headers:       headers,
			Body:          body,
			RemoteAddr:    r.RemoteAddr,
			XForwardedFor: r.Header.Get("X-Forwarded-For"),
			XRealIP:       r.Header.Get("X-Real-IP"),
		}

		// Проксируем запрос
		resp, err := proxyService.ProxyRequest(r.Context(), proxyReq)
		if err != nil {
			handleProxyError(w, err, log)
			return
		}

		// Копируем заголовки ответа
		for k, v := range resp.Headers {
			for _, val := range v {
				w.Header().Add(k, val)
			}
		}

		// Устанавливаем статус код
		w.WriteHeader(resp.StatusCode)

		// Копируем тело ответа
		if _, err := w.Write(resp.Body); err != nil {
			log.Error("Error writing response", logger.NewField("error", err.Error()))
		}
	}
}

// handleAuthError обрабатывает ошибки аутентификации
func handleAuthError(w http.ResponseWriter, err error, log logger.Logger) {
	if authErr, ok := err.(*auth.AuthError); ok {
		log.Warn("Authentication error", logger.NewField("code", authErr.Code), logger.NewField("message", authErr.Message))
		http.Error(w, authErr.Message, authErr.HTTPStatus())
		return
	}

	log.Error("Unknown authentication error", logger.NewField("error", err.Error()))
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// handleProxyError обрабатывает ошибки проксирования
func handleProxyError(w http.ResponseWriter, err error, log logger.Logger) {
	if proxyErr, ok := err.(*proxy.ProxyError); ok {
		log.Warn("Proxy error", logger.NewField("code", proxyErr.Code), logger.NewField("message", proxyErr.Message))
		http.Error(w, proxyErr.Message, proxyErr.HTTPStatus())
		return
	}

	log.Error("Unknown proxy error", logger.NewField("error", err.Error()))
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
