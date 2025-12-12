package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAppConfig(t *testing.T) {
	// Создаем временный файл конфигурации
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "app.json")

	configContent := `{
		"proxy": {
			"timeout_ms": 5000,
			"max_body_size_mb": 10,
			"default_headers": {
				"X-Powered-By": "Go-Proxy-Guard"
			}
		},
		"token": {
			"exp": 1440,
			"refresh_exp": 10080,
			"max_jwt_size_bytes": 4096,
			"alg_supported": ["HS256", "RS256"],
			"typ_supported": ["JWT"],
			"ip_whitelist": []
		},
		"redis": {
			"host": "localhost",
			"port": 6379,
			"password": "",
			"db": 0,
			"key_prefix": "go-proxy-guard:"
		},
		"logging": {
			"level": "info",
			"output": "/var/log/go-proxy-guard/proxy.log",
			"rotation": {
				"max_size_mb": 100,
				"max_age_days": 7,
				"max_backups": 10,
				"compress": true
			},
			"format": "json"
		}
	}`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Ошибка создания тестового файла: %v", err)
	}

	cfg, err := LoadAppConfig(configPath)
	if err != nil {
		t.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	if cfg.Proxy.TimeoutMS != 5000 {
		t.Errorf("Ожидался timeout_ms=5000, получен %d", cfg.Proxy.TimeoutMS)
	}

	if cfg.Token.Exp != 1440 {
		t.Errorf("Ожидался exp=1440, получен %d", cfg.Token.Exp)
	}

	if len(cfg.Token.AlgSupported) != 2 {
		t.Errorf("Ожидалось 2 алгоритма, получено %d", len(cfg.Token.AlgSupported))
	}
}

func TestAppConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  AppConfig
		wantErr bool
	}{
		{
			name: "валидная конфигурация",
			config: AppConfig{
				Proxy: ProxyConfig{
					TimeoutMS:     5000,
					MaxBodySizeMB: 10,
				},
				Token: TokenConfig{
					Exp:             1440,
					RefreshExp:      10080,
					MaxJWTSizeBytes: 4096,
					AlgSupported:    []string{"HS256"},
					TypSupported:    []string{"JWT"},
				},
				Redis: RedisConfig{
					Host:      "localhost",
					Port:      6379,
					KeyPrefix: "test:",
				},
				Logging: LoggingConfig{
					Level:  "info",
					Output: "/var/log/test.log",
					Format: "json",
					Rotation: RotationConfig{
						MaxSizeMB:  100,
						MaxAgeDays: 7,
						MaxBackups: 10,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "невалидный timeout_ms",
			config: AppConfig{
				Proxy: ProxyConfig{
					TimeoutMS:     0,
					MaxBodySizeMB: 10,
				},
			},
			wantErr: true,
		},
		{
			name: "пустой alg_supported",
			config: AppConfig{
				Proxy: ProxyConfig{
					TimeoutMS:     5000,
					MaxBodySizeMB: 10,
				},
				Token: TokenConfig{
					AlgSupported: []string{},
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
