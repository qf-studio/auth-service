.PHONY: build run test test-cover lint lint-fix fmt clean migrate-up migrate-down docker-up docker-down

# Build
build:
	go build -o bin/auth-service cmd/server/main.go

# Run
run:
	go run cmd/server/main.go

# Test
test:
	go test -race ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run

lint-fix:
	golangci-lint run --fix

# Format
fmt:
	go fmt ./...
	goimports -w .

# Migrations
migrate-up:
	go run cmd/migrate/main.go up

migrate-down:
	go run cmd/migrate/main.go down

# Docker
docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# Clean
clean:
	rm -rf bin/ coverage.out coverage.html
