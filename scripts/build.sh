#!/bin/bash

set -e

# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Сборка go-proxy-guard...${NC}"

# Определяем версию из git (если доступен)
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "dev")}

# Создаем директорию для бинарников
mkdir -p bin

# Собираем приложение
echo -e "${YELLOW}Компиляция приложения...${NC}"
go build -ldflags "-X main.version=${VERSION}" -o bin/proxy-guard ./cmd/proxy-guard

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Сборка завершена успешно${NC}"
    echo -e "${GREEN}Бинарник: bin/proxy-guard${NC}"
    ls -lh bin/proxy-guard
else
    echo -e "${YELLOW}✗ Ошибка сборки${NC}"
    exit 1
fi

