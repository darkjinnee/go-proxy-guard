package keys

import (
	"fmt"
	"strings"
)

// hsNamePrefix префикс файла для HMAC-ключа (hs256_ / hs512_).
func hsNamePrefix(algorithm Algorithm) (string, error) {
	switch algorithm {
	case AlgorithmHS256:
		return "hs256_", nil
	case AlgorithmHS512:
		return "hs512_", nil
	default:
		return "", fmt.Errorf("ожидался HS256 или HS512, получен %s", algorithm)
	}
}

// parseHSKeyFilename разбирает имя вида hs256_<id>.key или hs512_<id>.key.
func parseHSKeyFilename(name string) (algorithm Algorithm, keyID string, ok bool) {
	if !strings.HasSuffix(name, ".key") {
		return "", "", false
	}
	base := strings.TrimSuffix(name, ".key")
	switch {
	case strings.HasPrefix(base, "hs256_"):
		keyID = strings.TrimPrefix(base, "hs256_")
		if keyID == "" {
			return "", "", false
		}
		return AlgorithmHS256, keyID, true
	case strings.HasPrefix(base, "hs512_"):
		keyID = strings.TrimPrefix(base, "hs512_")
		if keyID == "" {
			return "", "", false
		}
		return AlgorithmHS512, keyID, true
	default:
		return "", "", false
	}
}
