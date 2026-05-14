package keys

import (
	"fmt"
	"strings"
)

// esNamePrefix префикс файла для ECDSA-ключа (es256_ / es512_).
func esNamePrefix(algorithm Algorithm) (string, error) {
	switch algorithm {
	case AlgorithmES256:
		return "es256_", nil
	case AlgorithmES512:
		return "es512_", nil
	default:
		return "", fmt.Errorf("ожидался ES256 или ES512, получен %s", algorithm)
	}
}

// parseESKeyFilename разбирает *.private / *.public для es256_ / es512_.
func parseESKeyFilename(name string) (algorithm Algorithm, keyID string, ok bool) {
	var base string
	switch {
	case strings.HasSuffix(name, ".private"):
		base = strings.TrimSuffix(name, ".private")
	case strings.HasSuffix(name, ".public"):
		base = strings.TrimSuffix(name, ".public")
	default:
		return "", "", false
	}

	switch {
	case strings.HasPrefix(base, "es256_"):
		keyID = strings.TrimPrefix(base, "es256_")
		if keyID == "" {
			return "", "", false
		}
		return AlgorithmES256, keyID, true
	case strings.HasPrefix(base, "es512_"):
		keyID = strings.TrimPrefix(base, "es512_")
		if keyID == "" {
			return "", "", false
		}
		return AlgorithmES512, keyID, true
	default:
		return "", "", false
	}
}
