# Contributing to Auth Service

Welcome! We appreciate your interest in contributing to the QuantFlow Studio auth service. This guide covers everything you need to get started.

## Development Setup

1. **Prerequisites**: Go 1.24+, Docker, Docker Compose
2. **Clone and start dependencies**:
   ```bash
   git clone https://github.com/qf-studio/auth-service.git
   cd auth-service
   docker-compose up -d postgres redis
   ```
3. **Run the service**:
   ```bash
   source .env && go run cmd/server/main.go
   ```
4. **Run tests**:
   ```bash
   go test -race ./...
   ```

## Code Style

- Run `go fmt ./...` and `goimports -w .` before committing
- Run `golangci-lint run` — all checks must pass
- Follow existing patterns in `internal/` (interface-driven, table-driven tests)
- Use structured errors: `fmt.Errorf("operation: %w", err)`
- Use `zap` for logging with correlation IDs

## Commit Format

```
type(scope): description (GH-NNN)
```

**Types**: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Example: `feat(auth): add password reset flow (GH-42)`

## Pull Request Checklist

- [ ] Code compiles: `go build ./...`
- [ ] Tests pass: `go test -race ./...`
- [ ] Linter passes: `golangci-lint run`
- [ ] New code has tests (90%+ coverage target)
- [ ] No secrets or `.env` files committed
- [ ] Commit messages follow the format above

## Security Contact

If you discover a security vulnerability, **do not** open a public issue. Email [security@quantflow.studio](mailto:security@quantflow.studio) with details and we will respond within 48 hours.

## License Agreement

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
