# Contributing to Auth Service

Thanks for your interest in contributing! This guide will get you set up quickly.

## Development Setup

```bash
# Clone and install dependencies
git clone https://github.com/qf-studio/auth-service.git
cd auth-service
go mod download

# Start infrastructure
docker-compose up -d postgres redis

# Run the service
cp .env.example .env  # adjust values as needed
source .env && go run cmd/server/main.go
```

## Code Style

- Run `go fmt ./...` and `goimports -w .` before committing
- Run `golangci-lint run` — all checks must pass
- Follow existing patterns in `internal/` (interface-driven, table-driven tests)
- Use `fmt.Errorf("context: %w", err)` for error wrapping
- Use `zap` for structured logging with correlation IDs

## Commit Format

```
type(scope): short description

# Types: feat, fix, docs, refactor, test, chore
# Examples:
#   feat(auth): add password reset flow
#   fix(token): handle expired refresh token edge case
#   test(middleware): add rate limiter concurrency tests
```

## Pull Request Checklist

- [ ] Code compiles: `go build ./...`
- [ ] Tests pass: `go test -race ./...`
- [ ] New code has tests (90%+ coverage target)
- [ ] Linter passes: `golangci-lint run`
- [ ] No secrets or `.env` files committed
- [ ] Commit messages follow the format above

## Security Disclosure

If you discover a security vulnerability, **do not open a public issue**. Instead, email [security@quantflow.studio](mailto:security@quantflow.studio) with details. We will respond within 48 hours.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
