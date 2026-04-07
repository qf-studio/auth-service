# Contributing to Auth Service

Contributions are welcome. This guide covers setup, standards, and the PR process.

## Development Setup

1. Clone the repository and install Go 1.24+.
2. Start dependencies: `docker-compose up -d postgres redis`
3. Run migrations: `go run cmd/migrate/main.go up`
4. Copy `.env.example` to `.env` and fill in required values.
5. Start the service: `source .env && go run cmd/server/main.go`
6. Run tests: `go test ./...`

## Code Style

- Follow standard Go conventions (`go fmt`, `goimports`, `golangci-lint`).
- Use `internal/` for all business logic; `pkg/` only for the shared SDK.
- Structured errors: `fmt.Errorf("operation failed: %w", err)`.
- Table-driven tests with `testify`.
- No config files — environment variables only.
- Manual dependency injection in `main()`.
- Use `zap` for logging with correlation IDs.

## Commit Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

feat(auth):   add password reset flow
fix(token):   handle expired refresh token edge case
test(rbac):   add role hierarchy tests
refactor(middleware): extract rate limiter
docs(readme): update configuration table
chore(ci):    upgrade Go version in workflow
```

Types: `feat`, `fix`, `test`, `refactor`, `docs`, `chore`

## Pull Request Checklist

- [ ] Code compiles: `go build ./...`
- [ ] Tests pass: `go test ./...`
- [ ] Linter clean: `golangci-lint run`
- [ ] New code includes tests (90%+ coverage target)
- [ ] No secrets or `.env` files committed
- [ ] Commit messages follow the format above
- [ ] PR description explains **what** and **why**

## Security Disclosure

If you discover a security vulnerability, **do not open a public issue**. Instead, email [security@quantflow.studio](mailto:security@quantflow.studio) with details. We will respond within 48 hours.

## License Agreement

By submitting a pull request, you agree that your contributions are licensed under the [MIT License](./LICENSE).
