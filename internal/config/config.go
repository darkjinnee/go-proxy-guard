package config

import "fmt"

// Config объединяет конфигурацию приложения и маршрутизации
type Config struct {
	App   *AppConfig
	Proxy *ProxyRoutingConfig
}

// LoadConfig загружает обе конфигурации (app.json и proxy.json)
func LoadConfig(appPath, proxyPath string) (*Config, error) {
	appCfg, err := LoadAppConfig(appPath)
	if err != nil {
		return nil, fmt.Errorf("error loading app.json: %w", err)
	}

	proxyCfg, err := LoadProxyConfig(proxyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading proxy.json: %w", err)
	}

	return &Config{
		App:   appCfg,
		Proxy: proxyCfg,
	}, nil
}
