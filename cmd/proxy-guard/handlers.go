package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"go-proxy-guard/internal/auth"
	"go-proxy-guard/internal/config"
	"go-proxy-guard/internal/logger"
	"go-proxy-guard/internal/proxy"
)

// handleGenerateTokens обрабатывает запрос на генерацию токенов
func handleGenerateTokens(authService *auth.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Извлекаем IP клиента
		clientIP := extractClientIP(r)

		// Читаем тело запроса
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error("Ошибка чтения тела запроса", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Парсим JSON
		var req auth.GenerateTokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Warn("Ошибка парсинга JSON", logger.NewField("error", err.Error()))
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
			log.Error("Ошибка кодирования ответа", logger.NewField("error", err.Error()))
		}
	}
}

// handleRefreshTokens обрабатывает запрос на обновление токенов
func handleRefreshTokens(authService *auth.Service, log logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Извлекаем IP клиента
		clientIP := extractClientIP(r)

		// Читаем тело запроса
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error("Ошибка чтения тела запроса", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Парсим JSON
		var req auth.RefreshTokenRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Warn("Ошибка парсинга JSON", logger.NewField("error", err.Error()))
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
			log.Error("Ошибка кодирования ответа", logger.NewField("error", err.Error()))
		}
	}
}

// handleProxy обрабатывает проксирование запросов
func handleProxy(proxyService *proxy.Service, log logger.Logger, cfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Читаем тело запроса с ограничением размера
		maxBodySize := int64(cfg.Proxy.MaxBodySizeMB) * 1024 * 1024
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err != nil {
			log.Error("Ошибка чтения тела запроса", logger.NewField("error", err.Error()))
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Проверяем размер тела
		if int64(len(body)) >= maxBodySize {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}

		// Формируем заголовки
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		// Создаем запрос для проксирования
		proxyReq := &proxy.ProxyRequest{
			Method:        r.Method,
			Path:          r.URL.Path,
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
			log.Error("Ошибка записи ответа", logger.NewField("error", err.Error()))
		}
	}
}

// handleAuthError обрабатывает ошибки аутентификации
func handleAuthError(w http.ResponseWriter, err error, log logger.Logger) {
	if authErr, ok := err.(*auth.AuthError); ok {
		log.Warn("Ошибка аутентификации", logger.NewField("code", authErr.Code), logger.NewField("message", authErr.Message))
		http.Error(w, authErr.Message, authErr.HTTPStatus())
		return
	}

	log.Error("Неизвестная ошибка аутентификации", logger.NewField("error", err.Error()))
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// handleProxyError обрабатывает ошибки проксирования
func handleProxyError(w http.ResponseWriter, err error, log logger.Logger) {
	if proxyErr, ok := err.(*proxy.ProxyError); ok {
		log.Warn("Ошибка проксирования", logger.NewField("code", proxyErr.Code), logger.NewField("message", proxyErr.Message))
		http.Error(w, proxyErr.Message, proxyErr.HTTPStatus())
		return
	}

	log.Error("Неизвестная ошибка проксирования", logger.NewField("error", err.Error()))
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

// extractClientIP извлекает IP адрес клиента из запроса
func extractClientIP(r *http.Request) string {
	// Приоритет: X-Forwarded-For > X-Real-IP > RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if idx := strings.Index(ip, ":"); idx != -1 {
				ip = ip[:idx]
			}
			return ip
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if idx := strings.Index(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		return ip
	}

	if r.RemoteAddr != "" {
		if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
			return r.RemoteAddr[:idx]
		}
		return r.RemoteAddr
	}

	return ""
}
