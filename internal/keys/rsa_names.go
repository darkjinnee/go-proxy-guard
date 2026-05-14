package keys

import (
	"fmt"
	"strings"
)

// rsaNamePrefix возвращает префикс имени файла для RSA-ключа (rsa256_ / rsa512_).
func rsaNamePrefix(algorithm Algorithm) (string, error) {
	switch algorithm {
	case AlgorithmRS256:
		return "rsa256_", nil
	case AlgorithmRS512:
		return "rsa512_", nil
	default:
		return "", fmt.Errorf("ожидался RS256 или RS512, получен %s", algorithm)
	}
}

// parseRSAKeyFilename из имени файла *.private / *.public возвращает алгоритм и ID ключа.
func parseRSAKeyFilename(name string) (algorithm Algorithm, keyID string, ok bool) {
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
	case strings.HasPrefix(base, "rsa256_"):
		keyID = strings.TrimPrefix(base, "rsa256_")
		if keyID == "" {
			return "", "", false
		}
		return AlgorithmRS256, keyID, true
	case strings.HasPrefix(base, "rsa512_"):
		keyID = strings.TrimPrefix(base, "rsa512_")
		if keyID == "" {
			return "", "", false
		}
		return AlgorithmRS512, keyID, true
	default:
		return "", "", false
	}
}
