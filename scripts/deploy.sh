#!/bin/bash

set -e

# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Деплой go-proxy-guard...${NC}"

# Проверяем наличие Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker не установлен${NC}"
    exit 1
fi

# Проверяем наличие docker-compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}docker-compose не установлен${NC}"
    exit 1
fi

# Переходим в директорию с docker-compose
cd "$(dirname "$0")/../deployments" || exit 1

# Собираем образ
echo -e "${YELLOW}Сборка Docker образа...${NC}"
docker-compose build

# Создаем необходимые директории на хосте
echo -e "${YELLOW}Создание директорий...${NC}"
sudo mkdir -p /var/lib/go-proxy-guard/keys
sudo mkdir -p /var/log/go-proxy-guard
sudo chmod 700 /var/lib/go-proxy-guard/keys
sudo chmod 755 /var/log/go-proxy-guard

# Запускаем контейнеры
echo -e "${YELLOW}Запуск контейнеров...${NC}"
docker-compose up -d

# Проверяем статус
echo -e "${YELLOW}Проверка статуса...${NC}"
docker-compose ps

echo -e "${GREEN}✓ Деплой завершен${NC}"
echo -e "${GREEN}Логи: docker-compose logs -f${NC}"
echo -e "${GREEN}Остановка: docker-compose down${NC}"

