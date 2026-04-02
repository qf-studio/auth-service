.PHONY: build test lint fmt clean

# Build
build:
	go build -o bin/auth-service cmd/server/main.go

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

# Clean
clean:
	rm -rf bin/ coverage.out coverage.html
