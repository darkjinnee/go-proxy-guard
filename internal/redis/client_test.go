package redis

import (
	"context"
	"testing"
	"time"

	"go-proxy-guard/internal/config"
)

// Тесты требуют запущенного Redis. Если Redis не доступен, тесты пропускаются.
func skipIfRedisNotAvailable(t *testing.T) {
	cfg := config.RedisConfig{
		Host:      "localhost",
		Port:      6379,
		KeyPrefix: "test:",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Skipf("Redis недоступен, пропускаем тесты: %v", err)
		return
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		t.Skipf("Redis недоступен, пропускаем тесты: %v", err)
	}
}

func TestNewClient(t *testing.T) {
	skipIfRedisNotAvailable(t)

	cfg := config.RedisConfig{
		Host:      "localhost",
		Port:      6379,
		KeyPrefix: "test:",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		t.Errorf("Ошибка ping: %v", err)
	}
}

func TestMarkTokenAsUsed(t *testing.T) {
	skipIfRedisNotAvailable(t)

	cfg := config.RedisConfig{
		Host:      "localhost",
		Port:      6379,
		KeyPrefix: "test:",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	jti := "test-jti-12345"

	// Помечаем токен как использованный
	err = client.MarkTokenAsUsed(ctx, jti, 60)
	if err != nil {
		t.Fatalf("Ошибка пометки токена: %v", err)
	}

	// Проверяем, что токен помечен как использованный
	used, err := client.IsTokenUsed(ctx, jti)
	if err != nil {
		t.Fatalf("Ошибка проверки токена: %v", err)
	}

	if !used {
		t.Error("Токен должен быть помечен как использованный")
	}

	// Очищаем после теста
	_ = client.DeleteToken(ctx, jti)
}

func TestIsTokenUsed(t *testing.T) {
	skipIfRedisNotAvailable(t)

	cfg := config.RedisConfig{
		Host:      "localhost",
		Port:      6379,
		KeyPrefix: "test:",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	jti := "test-jti-67890"

	// Проверяем неиспользованный токен
	used, err := client.IsTokenUsed(ctx, jti)
	if err != nil {
		t.Fatalf("Ошибка проверки токена: %v", err)
	}

	if used {
		t.Error("Токен не должен быть помечен как использованный")
	}

	// Помечаем токен как использованный
	err = client.MarkTokenAsUsed(ctx, jti, 60)
	if err != nil {
		t.Fatalf("Ошибка пометки токена: %v", err)
	}

	// Проверяем использованный токен
	used, err = client.IsTokenUsed(ctx, jti)
	if err != nil {
		t.Fatalf("Ошибка проверки токена: %v", err)
	}

	if !used {
		t.Error("Токен должен быть помечен как использованный")
	}

	// Очищаем после теста
	_ = client.DeleteToken(ctx, jti)
}

func TestDeleteToken(t *testing.T) {
	skipIfRedisNotAvailable(t)

	cfg := config.RedisConfig{
		Host:      "localhost",
		Port:      6379,
		KeyPrefix: "test:",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	jti := "test-jti-delete"

	// Помечаем токен как использованный
	err = client.MarkTokenAsUsed(ctx, jti, 60)
	if err != nil {
		t.Fatalf("Ошибка пометки токена: %v", err)
	}

	// Удаляем токен
	err = client.DeleteToken(ctx, jti)
	if err != nil {
		t.Fatalf("Ошибка удаления токена: %v", err)
	}

	// Проверяем, что токен удален
	used, err := client.IsTokenUsed(ctx, jti)
	if err != nil {
		t.Fatalf("Ошибка проверки токена: %v", err)
	}

	if used {
		t.Error("Токен должен быть удален")
	}
}

func TestGetTokenTTL(t *testing.T) {
	skipIfRedisNotAvailable(t)

	cfg := config.RedisConfig{
		Host:      "localhost",
		Port:      6379,
		KeyPrefix: "test:",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	ctx := context.Background()
	jti := "test-jti-ttl"
	ttlSeconds := 120

	// Помечаем токен как использованный с TTL
	err = client.MarkTokenAsUsed(ctx, jti, ttlSeconds)
	if err != nil {
		t.Fatalf("Ошибка пометки токена: %v", err)
	}

	// Получаем TTL
	ttl, err := client.GetTokenTTL(ctx, jti)
	if err != nil {
		t.Fatalf("Ошибка получения TTL: %v", err)
	}

	// TTL должен быть близок к установленному значению (с учетом небольшой задержки)
	if ttl <= 0 || ttl > int64(ttlSeconds) {
		t.Errorf("TTL должен быть в диапазоне 0-%d, получен %d", ttlSeconds, ttl)
	}

	// Очищаем после теста
	_ = client.DeleteToken(ctx, jti)
}

func TestHealthCheck(t *testing.T) {
	skipIfRedisNotAvailable(t)

	cfg := config.RedisConfig{
		Host:      "localhost",
		Port:      6379,
		KeyPrefix: "test:",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("Ошибка создания клиента: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	err = client.HealthCheck(ctx)
	if err != nil {
		t.Errorf("Ошибка health check: %v", err)
	}
}

func TestBuildKey(t *testing.T) {
	// Тест buildKey не требует подключения к Redis
	// Создаем клиент напрямую для теста
	client := &Client{
		keyPrefix: "test:",
	}

	jti := "test-jti-123"
	expected := "test:refresh_token:test-jti-123"
	actual := client.buildKey(jti)

	if actual != expected {
		t.Errorf("Ожидался ключ %s, получен %s", expected, actual)
	}
}
