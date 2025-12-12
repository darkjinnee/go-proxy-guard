.PHONY: build run test clean lint fmt vet help

# Переменные
APP_NAME := proxy-guard
CMD_DIR := cmd/proxy-guard
BIN_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Цвета для вывода
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

help: ## Показать справку
	@echo "$(GREEN)Доступные команды:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'

build: ## Собрать приложение
	@echo "$(GREEN)Сборка приложения...$(NC)"
	@mkdir -p $(BIN_DIR)
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BIN_DIR)/$(APP_NAME) ./$(CMD_DIR)
	@echo "$(GREEN)Готово: $(BIN_DIR)/$(APP_NAME)$(NC)"

run: ## Запустить приложение
	@echo "$(GREEN)Запуск приложения...$(NC)"
	@go run ./$(CMD_DIR)

test: ## Запустить тесты
	@echo "$(GREEN)Запуск тестов...$(NC)"
	@go test -v ./...

test-coverage: ## Запустить тесты с покрытием
	@echo "$(GREEN)Запуск тестов с покрытием...$(NC)"
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Отчет о покрытии: coverage.html$(NC)"

clean: ## Очистить артефакты сборки
	@echo "$(GREEN)Очистка...$(NC)"
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html
	@go clean

lint: ## Запустить линтер
	@echo "$(GREEN)Проверка кода линтером...$(NC)"
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "$(YELLOW)golangci-lint не установлен, пропускаем$(NC)"; \
	fi

fmt: ## Форматировать код
	@echo "$(GREEN)Форматирование кода...$(NC)"
	@go fmt ./...

vet: ## Запустить go vet
	@echo "$(GREEN)Проверка кода go vet...$(NC)"
	@go vet ./...

deps: ## Установить зависимости
	@echo "$(GREEN)Установка зависимостей...$(NC)"
	@go mod download
	@go mod tidy

tidy: ## Обновить go.mod и go.sum
	@echo "$(GREEN)Обновление go.mod и go.sum...$(NC)"
	@go mod tidy

.DEFAULT_GOAL := help

