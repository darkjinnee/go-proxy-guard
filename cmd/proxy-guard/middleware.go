package main

import (
	"net/http"
	"time"

	"go-proxy-guard/internal/clientip"
	"go-proxy-guard/internal/logger"
)

// loggingMiddleware создает middleware для логирования запросов
func loggingMiddleware(next http.Handler, log logger.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Создаем обертку для ResponseWriter для захвата статус кода
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// Выполняем следующий handler
		next.ServeHTTP(wrapped, r)

		// Логируем запрос
		duration := time.Since(start)
		log.Info("HTTP request processed",
			logger.NewField("method", r.Method),
			logger.NewField("path", r.URL.Path),
			logger.NewField("host", r.Host),
			logger.NewField("status_code", wrapped.statusCode),
			logger.NewField("duration_ms", duration.Milliseconds()),
			logger.NewField("client_ip", clientip.ClientIP(
				r.RemoteAddr,
				r.Header.Get("X-Forwarded-For"),
				r.Header.Get("X-Real-IP"),
			)),
		)
	})
}

// responseWriter обертка над http.ResponseWriter для захвата статус кода
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
