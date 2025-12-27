package keys

import (
	"crypto/rand"
	"fmt"
	"io"
)

// generateUUID генерирует UUID v4
func generateUUID() string {
	uuid := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, uuid); err != nil {
		// Fallback на простую генерацию, если crypto/rand недоступен
		panic(fmt.Sprintf("ошибка генерации UUID: %v", err))
	}

	// Устанавливаем версию (4) и вариант
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Версия 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Вариант 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

