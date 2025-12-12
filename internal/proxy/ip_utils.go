package proxy

import (
	"net"
	"strings"
)

// parseCIDR парсит CIDR сеть
func parseCIDR(cidr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return network, nil
}

// parseIP парсит IP адрес
func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}

// extractClientIP извлекает IP адрес клиента из запроса
func extractClientIP(remoteAddr, xForwardedFor, xRealIP string) string {
	// Приоритет: X-Forwarded-For > X-Real-IP > RemoteAddr
	if xForwardedFor != "" {
		// X-Forwarded-For может содержать несколько IP через запятую
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
