package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"go-proxy-guard/internal/config"
)

// Client представляет клиент Redis для работы с использованными токенами
type Client struct {
	rdb       *redis.Client
	keyPrefix string
}

// NewClient создает новый клиент Redis
func NewClient(cfg config.RedisConfig) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Проверяем подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("error connecting to Redis: %w", err)
	}

	return &Client{
		rdb:       rdb,
		keyPrefix: cfg.KeyPrefix,
	}, nil
}

// Close закрывает соединение с Redis
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Ping проверяет доступность Redis
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// buildKey формирует полный ключ с префиксом
func (c *Client) buildKey(jti string) string {
	return c.keyPrefix + "refresh_token:" + jti
}
