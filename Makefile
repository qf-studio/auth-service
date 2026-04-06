.PHONY: build run test test-cover bench bench-cpu bench-mem load-test lint lint-fix fmt clean migrate-up migrate-down docker-up docker-down

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

# Benchmarks
bench:
	go test -bench=. -benchmem -run=^$$ ./...

bench-cpu:
	mkdir -p profiles
	go test -bench=. -run=^$$ -cpuprofile=profiles/cpu.prof ./...
	@echo "CPU profile written to profiles/cpu.prof"
	@echo "View with: go tool pprof -http=:8080 profiles/cpu.prof"

bench-mem:
	mkdir -p profiles
	go test -bench=. -run=^$$ -memprofile=profiles/mem.prof -benchmem ./...
	@echo "Memory profile written to profiles/mem.prof"
	@echo "View with: go tool pprof -http=:8080 profiles/mem.prof"

# Load Testing (requires k6: https://k6.io)
load-test:
	@if ! command -v k6 >/dev/null 2>&1; then \
		echo "Error: k6 is not installed. Install from https://k6.io/docs/get-started/installation/"; \
		exit 1; \
	fi
	k6 run tests/load/scenarios.js

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
	rm -rf bin/ coverage.out coverage.html profiles/
