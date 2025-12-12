package proxy

import (
	"go-proxy-guard/internal/config"
	"go-proxy-guard/internal/keys"
	"go-proxy-guard/pkg/jwt"
)

// Service представляет сервис проксирования
type Service struct {
	appConfig   *config.AppConfig
	proxyConfig *config.ProxyRoutingConfig
	keyStore    keys.KeyStore
	jwtVal      jwt.Validator
}

// NewService создает новый сервис проксирования
func NewService(
	appConfig *config.AppConfig,
	proxyConfig *config.ProxyRoutingConfig,
	keyStore keys.KeyStore,
) *Service {
	return &Service{
		appConfig:   appConfig,
		proxyConfig: proxyConfig,
		keyStore:    keyStore,
		jwtVal:      jwt.NewValidator(),
	}
}

// ProxyRequest представляет запрос для проксирования
type ProxyRequest struct {
	Method        string
	Path          string
	Host          string
	Headers       map[string]string
	Body          []byte
	RemoteAddr    string
	XForwardedFor string
	XRealIP       string
}

// ProxyResponse представляет ответ от проксируемого сервиса
type ProxyResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}
