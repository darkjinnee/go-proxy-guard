package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProxyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "proxy.json")

	configContent := `[
		{
			"domain": "api.example.com",
			"routes": [
				{
					"match": {
						"path": "/v1/users/*",
						"method": ["GET", "POST"]
					},
					"forward_to": {
						"url": "http://users-service.internal:8080"
					}
				}
			]
		}
	]`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Ошибка создания тестового файла: %v", err)
	}

	cfg, err := LoadProxyConfig(configPath)
	if err != nil {
		t.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	if len(cfg.Domains) != 1 {
		t.Errorf("Ожидался 1 домен, получено %d", len(cfg.Domains))
	}

	domainCfg, exists := cfg.Domains["api.example.com"]
	if !exists {
		t.Fatal("Домен 'api.example.com' не найден")
	}

	if len(domainCfg.Routes) != 1 {
		t.Errorf("Ожидался 1 маршрут, получено %d", len(domainCfg.Routes))
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "домен с портом",
			host:     "api.example.com:8080",
			expected: "api.example.com",
		},
		{
			name:     "домен в верхнем регистре",
			host:     "API.EXAMPLE.COM",
			expected: "api.example.com",
		},
		{
			name:     "домен с пробелами",
			host:     "  api.example.com  ",
			expected: "api.example.com",
		},
		{
			name:     "обычный домен",
			host:     "api.example.com",
			expected: "api.example.com",
		},
	}

	cfg := &ProxyRoutingConfig{
		Domains: map[string]DomainConfig{
			"api.example.com": {
				Routes: []Route{
					{
						Match: RouteMatch{
							Path:   "/test",
							Method: []string{"GET"},
						},
						ForwardTo: RouteForwardTo{
							URL: "http://test:8080",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domainCfg, err := cfg.GetDomainConfig(tt.host)
			if err != nil {
				t.Fatalf("GetDomainConfig() error = %v", err)
			}

			if domainCfg == nil {
				t.Fatal("GetDomainConfig() вернул nil")
			}
		})
	}
}

func TestProxyRoutingConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ProxyRoutingConfig
		wantErr bool
	}{
		{
			name: "валидная конфигурация",
			config: ProxyRoutingConfig{
				Domains: map[string]DomainConfig{
					"api.example.com": {
						Routes: []Route{
							{
								Match: RouteMatch{
									Path:   "/test",
									Method: []string{"GET"},
								},
								ForwardTo: RouteForwardTo{
									URL: "http://test:8080",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "пустые domains",
			config: ProxyRoutingConfig{
				Domains: map[string]DomainConfig{},
			},
			wantErr: true,
		},
		{
			name: "пустые routes у домена",
			config: ProxyRoutingConfig{
				Domains: map[string]DomainConfig{
					"test.com": {
						Routes: []Route{},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRouteMatch_Validate(t *testing.T) {
	tests := []struct {
		name    string
		match   RouteMatch
		wantErr bool
	}{
		{
			name: "валидный match",
			match: RouteMatch{
				Path:   "/test",
				Method: []string{"GET", "POST"},
			},
			wantErr: false,
		},
		{
			name: "wildcard метод",
			match: RouteMatch{
				Path:   "/test",
				Method: []string{"*"},
			},
			wantErr: false,
		},
		{
			name: "пустой path",
			match: RouteMatch{
				Path:   "",
				Method: []string{"GET"},
			},
			wantErr: true,
		},
		{
			name: "пустой method",
			match: RouteMatch{
				Path:   "/test",
				Method: []string{},
			},
			wantErr: true,
		},
		{
			name: "wildcard с другими методами",
			match: RouteMatch{
				Path:   "/test",
				Method: []string{"*", "GET"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.match.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
