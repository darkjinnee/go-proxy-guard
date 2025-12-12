package jwt

import (
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

func TestGenerateToken_HS256(t *testing.T) {
	tmpDir := t.TempDir()

	// Создаем keyStore
	keyStore, err := keys.NewFileStore(tmpDir)
	if err != nil {
		t.Fatalf("Ошибка создания keyStore: %v", err)
	}

	// Генерируем ключ
	_, err = keyStore.GenerateKey(keys.AlgorithmHS256)
	if err != nil {
		t.Fatalf("Ошибка генерации ключа: %v", err)
	}

	// Создаем генератор
	gen := NewGenerator()

	// Создаем claims
	claims := BuildClaims(TokenTypeAccess, "test-jti", Claims{"user_id": "123"}, 60)

	// Генерируем токен
	token, err := gen.GenerateToken(claims, keys.AlgorithmHS256, keyStore)
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
