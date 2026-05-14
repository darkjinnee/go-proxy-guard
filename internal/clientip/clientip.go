package clientip

import (
	"net"
	"strings"
)

// ClientIP возвращает IP клиента: X-Forwarded-For → X-Real-IP → RemoteAddr.
// Первый адрес из X-Forwarded-For; далее нормализация через Normalize.
func ClientIP(remoteAddr, xForwardedFor, xRealIP string) string {
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return Normalize(ip)
			}
		}
	}

	if xRealIP != "" {
		return Normalize(strings.TrimSpace(xRealIP))
	}

	if remoteAddr != "" {
		return Normalize(remoteAddr)
	}

	return ""
}

// Normalize убирает порт и квадратные скобки IPv6, возвращает host-часть адреса.
func Normalize(addr string) string {
	addr = strings.TrimSpace(addr)

	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		if idx := strings.Index(addr, "]:"); idx != -1 {
			return addr[1:idx]
		}
		return addr[1 : len(addr)-1]
	}

	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}

	if net.ParseIP(addr) != nil {
		return addr
	}

	lastColon := strings.LastIndex(addr, ":")
	if lastColon != -1 {
		afterColon := addr[lastColon+1:]
		if isNumeric(afterColon) {
			potentialIP := addr[:lastColon]
			if net.ParseIP(potentialIP) != nil {
				return potentialIP
			}
		}
	}

	return addr
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
