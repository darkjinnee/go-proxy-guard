package jwt

import (
	"encoding/base64"
	"strings"
	"testing"

	"go-proxy-guard/internal/keys"
)

func TestBuildClaims(t *testing.T) {
	jti := "test-jti-12345"
	userClaims := Claims{
		"user_id":  "12345",
		"username": "testuser",
		"role":     "admin",
	}
	expMinutes := 60

	claims := BuildClaims(TokenTypeAccess, jti, userClaims, expMinutes)

	if claims["type"] != "access" {
		t.Errorf("Ожидался type=access, получен %v", claims["type"])
	}

	if claims["jti"] != jti {
		t.Errorf("Ожидался jti=%s, получен %v", jti, claims["jti"])
	}

	if claims["user_id"] != "12345" {
		t.Errorf("Ожидался user_id=12345, получен %v", claims["user_id"])
	}

	exp, ok := claims["exp"].(int64)
	if !ok || exp <= 0 {
		t.Errorf("exp должен быть положительным int64, получен %v", claims["exp"])
	}

	iat, ok := claims["iat"].(int64)
	if !ok || iat <= 0 {
		t.Errorf("iat должен быть положительным int64, получен %v", claims["iat"])
	}
}

func TestGenerateToken_RS256(t *testing.T) {
	tmpDir := t.TempDir()

	// Создаем keyStore
	keyStore, err := keys.NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("Ошибка создания keyStore: %v", err)
	}

	// Генерируем ключ
	_, err = keyStore.GenerateKey(keys.AlgorithmRS256)
	if err != nil {
		t.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// Создаем генератор
	gen := NewGenerator()

	// Создаем claims
	claims := BuildClaims(TokenTypeAccess, "test-jti", Claims{"user_id": "123"}, 60)

	// Генерируем токен
	token, err := gen.GenerateToken(claims, keys.AlgorithmRS256, keyStore, "")
	if err != nil {
		t.Fatalf("Ошибка генерации токена: %v", err)
	}

	if token == "" {
		t.Error("Токен не должен быть пустым")
	}

	// Проверяем, что токен имеет правильный формат (три части, разделенные точками)
	if len(token) == 0 {
		t.Error("Токен должен содержать данные")
	}
}

func TestGenerateToken_WithKid(t *testing.T) {
	tmpDir := t.TempDir()

	// Создаем keyStore
	keyStore, err := keys.NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("Ошибка создания keyStore: %v", err)
	}

	// Генерируем ключ
	key, err := keyStore.GenerateKey(keys.AlgorithmRS256)
	if err != nil {
		t.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// Создаем генератор
	gen := NewGenerator()

	// Создаем claims
	claims := BuildClaims(TokenTypeAccess, "test-jti", Claims{"user_id": "123"}, 60)

	// Генерируем токен с указанным kid
	customKid := "custom-key-id-123"
	token, err := gen.GenerateToken(claims, keys.AlgorithmRS256, keyStore, customKid)
	if err != nil {
		t.Fatalf("Ошибка генерации токена: %v", err)
	}

	// Проверяем, что kid присутствует в заголовке токена
	// Декодируем header токена
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		t.Fatal("Токен должен содержать минимум 2 части")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("Ошибка декодирования header: %v", err)
	}

	headerStr := string(headerBytes)
	if !strings.Contains(headerStr, `"kid"`) {
		t.Error("Заголовок токена должен содержать kid")
	}

	if !strings.Contains(headerStr, customKid) {
		t.Errorf("Заголовок токена должен содержать kid=%s, но содержит: %s", customKid, headerStr)
	}

	// Тестируем генерацию без kid (должен использоваться ID ключа)
	token2, err := gen.GenerateToken(claims, keys.AlgorithmRS256, keyStore, "")
	if err != nil {
		t.Fatalf("Ошибка генерации токена без kid: %v", err)
	}

	parts2 := strings.Split(token2, ".")
	headerBytes2, err := base64.RawURLEncoding.DecodeString(parts2[0])
	if err != nil {
		t.Fatalf("Ошибка декодирования header: %v", err)
	}

	headerStr2 := string(headerBytes2)
	if !strings.Contains(headerStr2, `"kid"`) {
		t.Error("Заголовок токена должен содержать kid даже если не указан явно")
	}

	if !strings.Contains(headerStr2, key.Metadata.ID) {
		t.Errorf("Заголовок токена должен содержать ID ключа=%s, но содержит: %s", key.Metadata.ID, headerStr2)
	}
}

func TestClaims_GetUserClaims(t *testing.T) {
	claims := Claims{
		"type":     "access",
		"jti":      "test-jti",
		"exp":      int64(1234567890),
		"iat":      int64(1234567890),
		"user_id":  "12345",
		"username": "testuser",
		"role":     "admin",
	}

	userClaims := claims.GetUserClaims()

	// Проверяем, что стандартные claims исключены
	if _, ok := userClaims["type"]; ok {
		t.Error("type не должен быть в userClaims")
	}
	if _, ok := userClaims["jti"]; ok {
		t.Error("jti не должен быть в userClaims")
	}
	if _, ok := userClaims["exp"]; ok {
		t.Error("exp не должен быть в userClaims")
	}
	if _, ok := userClaims["iat"]; ok {
		t.Error("iat не должен быть в userClaims")
	}

	// Проверяем, что пользовательские claims присутствуют
	if userClaims["user_id"] != "12345" {
		t.Error("user_id должен быть в userClaims")
	}
	if userClaims["username"] != "testuser" {
		t.Error("username должен быть в userClaims")
	}
	if userClaims["role"] != "admin" {
		t.Error("role должен быть в userClaims")
	}
}
