package proxy

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"

	"go-proxy-guard/internal/config"
)

// findRoute находит подходящий маршрут для запроса
func (s *Service) findRoute(domain, path, method, clientIP string) (*config.Route, error) {
	// Получаем конфигурацию домена
	domainCfg, err := s.proxyConfig.GetDomainConfig(domain)
	if err != nil {
		return nil, fmt.Errorf("домен не найден: %w", err)
	}

	// Ищем подходящий маршрут
	for _, route := range domainCfg.Routes {
		// Проверяем соответствие пути
		if !s.matchPath(route.Match.Path, path) {
			continue
		}

		// Проверяем HTTP метод
		if !s.matchMethod(route.Match.Method, method) {
			continue
		}

		// Проверяем IP whitelist/blacklist
		if err := s.checkIPAccess(clientIP, route.Match.IPWhitelist, route.Match.IPBlacklist); err != nil {
			return nil, err
		}

		// Маршрут найден
		return &route, nil
	}

	return nil, fmt.Errorf("маршрут не найден для пути %s", path)
}

// matchPath проверяет соответствие пути паттерну
func (s *Service) matchPath(pattern, path string) bool {
	// Компилируем glob паттерн
	g := glob.MustCompile(pattern)
	return g.Match(path)
}

// matchMethod проверяет соответствие HTTP метода
func (s *Service) matchMethod(allowedMethods []string, method string) bool {
	for _, m := range allowedMethods {
		if m == "*" || strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// checkIPAccess проверяет доступ по IP whitelist/blacklist
func (s *Service) checkIPAccess(clientIP string, whitelist, blacklist []string) error {
	// Проверяем blacklist
	if len(blacklist) > 0 {
		if s.isIPInList(clientIP, blacklist) {
			return fmt.Errorf("IP адрес %s заблокирован", clientIP)
		}
	}

	// Проверяем whitelist
	if len(whitelist) > 0 {
		if !s.isIPInList(clientIP, whitelist) {
			return fmt.Errorf("IP адрес %s не входит в whitelist", clientIP)
		}
	}

	return nil
}

// isIPInList проверяет, входит ли IP в список
func (s *Service) isIPInList(clientIP string, list []string) bool {
	for _, item := range list {
		if s.matchIP(clientIP, item) {
			return true
		}
	}
	return false
}

// matchIP проверяет соответствие IP адреса паттерну (точное совпадение или CIDR)
func (s *Service) matchIP(ip, pattern string) bool {
	// Точное совпадение
	if ip == pattern {
		return true
	}

	// CIDR сеть
	if strings.Contains(pattern, "/") {
		network, err := parseCIDR(pattern)
		if err != nil {
			return false
		}

		ipAddr := parseIP(ip)
		if ipAddr == nil {
			return false
		}

		return network.Contains(ipAddr)
	}

	return false
}
