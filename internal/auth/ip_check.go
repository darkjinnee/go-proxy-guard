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

	// Нормализуем IP адрес (убираем квадратные скобки для IPv6)
	normalizedIP := normalizeIP(clientIP)
	
	ip := net.ParseIP(normalizedIP)
	if ip == nil {
		return fmt.Errorf("невалидный IP адрес: %s", clientIP)
	}

	// Автоматически разрешаем localhost адреса (для разработки)
	if ip.IsLoopback() {
		return nil
	}

	for _, allowed := range whitelist {
		// Нормализуем разрешенный IP для сравнения
		normalizedAllowed := normalizeIP(allowed)
		
		// Проверяем точное совпадение IP
		if normalizedAllowed == normalizedIP || allowed == clientIP {
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
				return normalizeIP(ip)
			}
		}
	}

	if xRealIP != "" {
		ip := strings.TrimSpace(xRealIP)
		return normalizeIP(ip)
	}

	// Извлекаем IP из RemoteAddr (формат: "ip:port" или "[ip]:port" для IPv6)
	if remoteAddr != "" {
		return normalizeIP(remoteAddr)
	}

	return ""
}

// normalizeIP нормализует IP адрес, убирая порт и квадратные скобки
func normalizeIP(addr string) string {
	// Убираем пробелы
	addr = strings.TrimSpace(addr)
	
	// Если адрес уже в квадратных скобках без порта (например, [::1])
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		// Проверяем, есть ли порт после скобок
		if idx := strings.Index(addr, "]:"); idx != -1 {
			// Формат: [::1]:8080
			host := addr[1:idx]
			return host
		}
		// Формат: [::1] без порта
		return addr[1 : len(addr)-1]
	}

	// Пробуем распарсить как адрес с портом (формат: [::1]:8080 или 127.0.0.1:8080)
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}

	// Если не удалось распарсить, проверяем, это валидный IP адрес
	if net.ParseIP(addr) != nil {
		return addr
	}

	// Пытаемся извлечь IP, удаляя все после последнего двоеточия (для IPv4)
	// Для IPv4 формат: 127.0.0.1:8080
	lastColon := strings.LastIndex(addr, ":")
	if lastColon != -1 {
		// Проверяем, не является ли это частью IPv6 адреса
		// Если после последнего двоеточия только цифры, это порт
		afterColon := addr[lastColon+1:]
		if isNumeric(afterColon) {
			potentialIP := addr[:lastColon]
			// Проверяем, это валидный IP
			if net.ParseIP(potentialIP) != nil {
				return potentialIP
			}
		}
	}

	return addr
}

// isNumeric проверяет, состоит ли строка только из цифр
func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
