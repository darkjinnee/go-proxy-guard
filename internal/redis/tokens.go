package redis

import (
	"context"
	"fmt"
	"time"
)

// MarkTokenAsUsed помечает refresh токен как использованный
// jti - идентификатор токена (JWT ID)
// ttlSeconds - время жизни в секундах (время жизни refresh_token)
func (c *Client) MarkTokenAsUsed(ctx context.Context, jti string, ttlSeconds int) error {
	if jti == "" {
		return fmt.Errorf("jti cannot be empty")
	}

	if ttlSeconds <= 0 {
		return fmt.Errorf("ttl must be greater than 0")
	}

	key := c.buildKey(jti)

	// Сохраняем токен с TTL
	// Значение может быть любым, например timestamp или просто "1"
	err := c.rdb.Set(ctx, key, "1", time.Duration(ttlSeconds)*time.Second).Err()
	if err != nil {
		return fmt.Errorf("error saving token to Redis: %w", err)
	}

	return nil
}

// IsTokenUsed проверяет, был ли refresh токен уже использован
// Возвращает true, если токен использован, false если нет
func (c *Client) IsTokenUsed(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, fmt.Errorf("jti cannot be empty")
	}

	key := c.buildKey(jti)

	// Проверяем существование ключа
	exists, err := c.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("error checking token in Redis: %w", err)
	}

	return exists > 0, nil
}

// DeleteToken удаляет запись о использованном токене (для отзыва токенов)
func (c *Client) DeleteToken(ctx context.Context, jti string) error {
	if jti == "" {
		return fmt.Errorf("jti cannot be empty")
	}

	key := c.buildKey(jti)

	err := c.rdb.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("error deleting token from Redis: %w", err)
	}

	return nil
}

// GetTokenTTL возвращает оставшееся время жизни записи о токене в секундах
func (c *Client) GetTokenTTL(ctx context.Context, jti string) (int64, error) {
	if jti == "" {
		return 0, fmt.Errorf("jti cannot be empty")
	}

	key := c.buildKey(jti)

	ttl, err := c.rdb.TTL(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("error getting token TTL: %w", err)
	}

	return int64(ttl.Seconds()), nil
}
