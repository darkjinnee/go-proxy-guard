package proxy

import (
	"fmt"
	"regexp"
	"strings"
)

// rewritePath переписывает путь запроса согласно правилу rewrite_path
func rewritePath(originalPath, pathPattern, rewritePattern string) (string, error) {
	if rewritePattern == "" {
		return originalPath, nil
	}

	// Преобразуем glob паттерн в regex для захвата групп
	regexPattern := globToRegex(pathPattern)
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return "", fmt.Errorf("ошибка компиляции regex: %w", err)
	}

	// Находим совпадения
	matches := re.FindStringSubmatch(originalPath)
	if len(matches) == 0 {
		return originalPath, nil
	}

	// Заменяем плейсхолдеры $1, $2, $3 и т.д.
	result := rewritePattern
	for i := 1; i < len(matches); i++ {
		placeholder := fmt.Sprintf("$%d", i)
		result = strings.ReplaceAll(result, placeholder, matches[i])
	}

	return result, nil
}

// globToRegex преобразует glob паттерн в regex
func globToRegex(pattern string) string {
	// Экранируем специальные символы regex
	pattern = regexp.QuoteMeta(pattern)

	// Заменяем glob символы на regex
	pattern = strings.ReplaceAll(pattern, `\*\*`, `(.*)`)  // ** -> (.*)
	pattern = strings.ReplaceAll(pattern, `\*`, `([^/]+)`) // * -> ([^/]+)

	return "^" + pattern + "$"
}
