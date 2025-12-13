package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ProxyRoutingConfig представляет конфигурацию маршрутизации прокси
type ProxyRoutingConfig struct {
	Proxy   ProxyRoutingProxyConfig `json:"proxy"`
	Domains map[string]DomainConfig `json:"domains"`
}

// ProxyRoutingProxyConfig представляет глобальные настройки проксирования в proxy.json
type ProxyRoutingProxyConfig struct {
	TimeoutMS      int               `json:"timeout_ms"`
	MaxBodySizeMB  int               `json:"max_body_size_mb"`
	DefaultHeaders map[string]string `json:"default_headers,omitempty"`
}

// DomainConfig представляет конфигурацию маршрутов для домена
type DomainConfig struct {
	Routes []Route `json:"routes"`
}

// Route представляет правило маршрутизации
type Route struct {
	Name      string         `json:"name,omitempty"`
	Match     RouteMatch     `json:"match"`
	ForwardTo RouteForwardTo `json:"forward_to"`
}

// RouteMatch представляет условия совпадения запроса с маршрутом
type RouteMatch struct {
	Path         string   `json:"path"`
	Method       []string `json:"method"`
	HostOverride *string  `json:"host_override,omitempty"`
	IPWhitelist  []string `json:"ip_whitelist,omitempty"`
	IPBlacklist  []string `json:"ip_blacklist,omitempty"`
}

// RouteForwardTo представляет конфигурацию проксирования запроса
type RouteForwardTo struct {
	URL         string            `json:"url"`
	TimeoutMS   *int              `json:"timeout_ms,omitempty"`
	RewritePath *string           `json:"rewrite_path,omitempty"`
	AddHeaders  map[string]string `json:"add_headers,omitempty"`
}

// LoadProxyConfig загружает конфигурацию маршрутизации из файла
func LoadProxyConfig(path string) (*ProxyRoutingConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg ProxyRoutingConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("error validating config: %w", err)
	}

	return &cfg, nil
}

// Validate проверяет корректность конфигурации маршрутизации
func (c *ProxyRoutingConfig) Validate() error {
	if err := c.Proxy.Validate(); err != nil {
		return fmt.Errorf("proxy: %w", err)
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("domains cannot be empty")
	}

	for domain, domainCfg := range c.Domains {
		if err := domainCfg.Validate(); err != nil {
			return fmt.Errorf("domain %s: %w", domain, err)
		}
	}

	return nil
}

// Validate проверяет корректность глобальных настроек проксирования
func (c *ProxyRoutingProxyConfig) Validate() error {
	if c.TimeoutMS <= 0 {
		return fmt.Errorf("timeout_ms must be greater than 0")
	}

	if c.MaxBodySizeMB <= 0 {
		return fmt.Errorf("max_body_size_mb must be greater than 0")
	}

	return nil
}

// Validate проверяет корректность конфигурации домена
func (c *DomainConfig) Validate() error {
	if len(c.Routes) == 0 {
		return fmt.Errorf("routes cannot be empty")
	}

	for i, route := range c.Routes {
		if err := route.Validate(); err != nil {
			return fmt.Errorf("route[%d]: %w", i, err)
		}
	}

	return nil
}

// Validate проверяет корректность правила маршрутизации
func (r *Route) Validate() error {
	if err := r.Match.Validate(); err != nil {
		return fmt.Errorf("match: %w", err)
	}

	if err := r.ForwardTo.Validate(); err != nil {
		return fmt.Errorf("forward_to: %w", err)
	}

	return nil
}

// Validate проверяет корректность условий совпадения
func (m *RouteMatch) Validate() error {
	if m.Path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	if len(m.Method) == 0 {
		return fmt.Errorf("method cannot be empty")
	}

	// Проверка, что если указан "*", то это единственный метод
	hasWildcard := false
	for _, method := range m.Method {
		if method == "*" {
			if hasWildcard {
				return fmt.Errorf("method '*' can only be specified once")
			}
			hasWildcard = true
		}
	}

	if hasWildcard && len(m.Method) > 1 {
		return fmt.Errorf("method '*' cannot be specified together with other methods")
	}

	return nil
}

// Validate проверяет корректность конфигурации проксирования
func (f *RouteForwardTo) Validate() error {
	if f.URL == "" {
		return fmt.Errorf("url cannot be empty")
	}

	// Базовая проверка формата URL
	if !strings.HasPrefix(f.URL, "http://") && !strings.HasPrefix(f.URL, "https://") {
		return fmt.Errorf("url must start with http:// or https://")
	}

	if f.TimeoutMS != nil && *f.TimeoutMS <= 0 {
		return fmt.Errorf("timeout_ms must be greater than 0")
	}

	return nil
}

// GetDomainConfig возвращает конфигурацию для указанного домена
// Выполняет нормализацию домена (приведение к нижнему регистру, удаление порта)
func (c *ProxyRoutingConfig) GetDomainConfig(host string) (*DomainConfig, error) {
	// Нормализация домена
	domain := normalizeDomain(host)

	cfg, exists := c.Domains[domain]
	if !exists {
		return nil, fmt.Errorf("domain '%s' not found in configuration", domain)
	}

	return &cfg, nil
}

// normalizeDomain нормализует домен: приводит к нижнему регистру и удаляет порт
func normalizeDomain(host string) string {
	// Удаление порта
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Приведение к нижнему регистру
	return strings.ToLower(strings.TrimSpace(host))
}
