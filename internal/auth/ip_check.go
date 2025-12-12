package auth

import (
	"fmt"
	"net"
	"strings"
)

// checkIPWhitelist проверяет, входит ли IP адрес в whitelist
func checkIPWhitelist(clientIP string, whitelist []string) error {
	if len(whitelist) == 0 {
		return nil // Whitelist не настроен, доступ разрешен
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return fmt.Errorf("невалидный IP адрес: %s", clientIP)
	}

	for _, allowed := range whitelist {
		// Проверяем точное совпадение IP
		if allowed == clientIP {
			return nil
		}

		// Проверяем CIDR сеть
		if strings.Contains(allowed, "/") {
			_, network, err := net.ParseCIDR(allowed)
			if err != nil {
				continue // Пропускаем невалидные CIDR
			}

			if network.Contains(ip) {
				return nil
			}
		}
	}

	return fmt.Errorf("IP адрес %s не входит в whitelist", clientIP)
}

// extractClientIP извлекает IP адрес клиента из запроса
// Проверяет заголовок X-Forwarded-For, затем X-Real-IP, затем RemoteAddr
func extractClientIP(remoteAddr, xForwardedFor, xRealIP string) string {
	// Приоритет: X-Forwarded-For > X-Real-IP > RemoteAddr
	if xForwardedFor != "" {
		// X-Forwarded-For может содержать несколько IP через запятую
		// Берем первый (оригинальный IP клиента)
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				// Удаляем порт, если есть
				if idx := strings.Index(ip, ":"); idx != -1 {
					ip = ip[:idx]
				}
				return ip
			}
		}
	}

	if xRealIP != "" {
		ip := strings.TrimSpace(xRealIP)
		if idx := strings.Index(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		return ip
	}

	// Извлекаем IP из RemoteAddr (формат: "ip:port")
	if remoteAddr != "" {
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			return remoteAddr[:idx]
		}
		return remoteAddr
	}

	return ""
}
