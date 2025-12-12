package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// HealthCheck проверяет состояние подключения к Redis
func (c *Client) HealthCheck(ctx context.Context) error {
	// Создаем контекст с таймаутом
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Проверяем подключение
	if err := c.Ping(checkCtx); err != nil {
		return fmt.Errorf("Redis недоступен: %w", err)
	}

	return nil
}

// GetStats возвращает статистику подключения к Redis
func (c *Client) GetStats(ctx context.Context) (*Stats, error) {
	info, err := c.rdb.Info(ctx, "stats").Result()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения статистики: %w", err)
	}

	poolStats := c.rdb.PoolStats()

	return &Stats{
		PoolStats: poolStats,
		Info:      info,
	}, nil
}

// Stats представляет статистику подключения к Redis
type Stats struct {
	PoolStats *redis.PoolStats
	Info      string
}
