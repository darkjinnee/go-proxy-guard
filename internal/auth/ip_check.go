package auth

import (
	"fmt"
	"net"
	"strings"

	"go-proxy-guard/internal/clientip"
)

// checkIPWhitelist проверяет, входит ли IP адрес в whitelist
func checkIPWhitelist(clientIP string, whitelist []string) error {
	if len(whitelist) == 0 {
		return nil // Whitelist не настроен, доступ разрешен
	}

	normalizedIP := clientip.Normalize(clientIP)

	ip := net.ParseIP(normalizedIP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", clientIP)
	}

	if ip.IsLoopback() {
		return nil
	}

	for _, allowed := range whitelist {
		normalizedAllowed := clientip.Normalize(allowed)

		if normalizedAllowed == normalizedIP || allowed == clientIP {
			return nil
		}

		if strings.Contains(allowed, "/") {
			_, network, err := net.ParseCIDR(allowed)
			if err != nil {
				continue
			}

			if network.Contains(ip) {
				return nil
			}
		}
	}

	return fmt.Errorf("IP address %s is not in whitelist", clientIP)
}
