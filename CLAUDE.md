# Auth Service - Claude Code Configuration

## Context

Authentication service for the QuantFlow Studio ecosystem.
Serves two client types: **Users** (humans) and **Systems** (services + AI agents).

**Tech Stack**: Go 1.24+, Gin, PostgreSQL (pgx/v5), Redis (go-redis/v9), JWT (ES256/EdDSA)
**Security Target**: NIST SP 800-63-4 AAL2
**Repo**: github.com/qf-studio/auth-service

**Last Updated**: 2026-02-24
**Navigator Version**: 6.2.1

---

## Navigator Quick Start

**Every session begins with**:
```
"Start my Navigator session"
```

This loads `.agent/DEVELOPMENT-README.md` (your project navigator) which provides:
- Documentation index and "when to read what" guide
- Current task context from PM tool (if configured)
- Quick start guides and integration status

**Core workflow**:
1. **Start session** -> Loads navigator automatically
2. **Load task docs** -> Only what's needed for current work
3. **Implement** -> Follow project patterns below
4. **Document** -> "Archive TASK-XX documentation" when complete
5. **Compact** -> "Clear context and preserve markers" after isolated tasks

**Natural language commands**:
- "Start my Navigator session" (begin work)
- "Archive TASK-XX documentation" (after completion)
- "Create an SOP for debugging [issue]" (document solution)
- "Clear context and preserve markers" (after sub-tasks)

---

## Essential Commands

### Development
```bash
# Start dependencies
docker-compose up -d postgres redis

# Run the service
go run cmd/server/main.go

# Run with environment file
source .env && go run cmd/server/main.go

# Run migrations
go run cmd/migrate/main.go up
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage and race detection
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific component tests
go test ./internal/auth -v
go test ./internal/token -v
go test ./internal/middleware -v
```

### Code Quality
```bash
go fmt ./...
goimports -w .
golangci-lint run
go build -o bin/auth-service cmd/server/main.go
```

---

## Project-Specific Code Standards

### General Standards
- **Architecture**: KISS, DRY, SOLID principles
- **Testing**: High coverage (backend 90%+), table-driven tests, mock interfaces
- **Security**: NIST SP 800-63-4 compliance, extra scrutiny on all security aspects
- **Patterns**: Interface-driven, factory pattern, env-based config, structured logging

### Go Standards
- Use `internal/` for all business logic (not importable externally)
- Use `pkg/` only for shared SDK (authclient)
- Env vars for config (no config files)
- Manual DI in main() (no DI container)
- Structured errors with context (`fmt.Errorf("operation failed: %w", err)`)
- zap for logging with correlation IDs
- Table-driven tests with testify

### Security Standards
- Argon2id for password hashing (m=19MiB, t=2, p=1)
- ES256 or EdDSA for JWT signing (asymmetric only)
- Token prefixes: `qf_at_`, `qf_rt_`, `qf_ac_`, `qf_ak_`
- Store only token signatures in DB (never full tokens)
- 128-bit salt, HMAC pepper for passwords
- TLS 1.3 enforced
- NIST password policy (15-char min, no composition rules, no rotation)
- Breached password blocklist check

---

## Forbidden Actions

### Navigator Violations (HIGHEST PRIORITY)
- NEVER load all `.agent/` docs at once (defeats token optimization)
- NEVER skip reading DEVELOPMENT-README.md navigator

### General Violations
- No Claude Code mentions in commits/code
- No package.json modifications without approval
- Never commit secrets/API keys/.env files
- Don't delete tests without replacement
- Never store full tokens in the database
- Never use symmetric JWT signing (HS256) for access tokens
- Never implement periodic password rotation
- Never add password composition rules (uppercase/symbol requirements)

---

## Documentation Structure

```
.agent/
├── DEVELOPMENT-README.md      # Navigator (always load first)
├── tasks/                     # Implementation plans
├── system/                    # Architecture docs
│   ├── project-architecture.md
│   ├── security-profile.md
│   ├── client-model.md
│   └── tech-decisions.md
└── sops/                      # Standard Operating Procedures
    ├── integrations/
    ├── debugging/
    ├── development/
    └── deployment/
```

**Token-efficient loading**:
- Navigator: ~2k tokens (always)
- Current task: ~3k tokens (as needed)
- System docs: ~5k tokens (when relevant)
- SOPs: ~2k tokens (if required)
- **Total**: ~12k vs ~150k loading everything

---

## Configuration

Navigator config in `.agent/.nav-config.json`:

```json
{
  "version": "6.2.1",
  "project_management": "github",
  "task_prefix": "TASK",
  "team_chat": "none",
  "auto_load_navigator": true,
  "compact_strategy": "conservative"
}
```

---

## Commit Guidelines

- **Format**: `type(scope): description`
- **Reference ticket**: `feat(auth): implement OAuth login TASK-XX`
- **Types**: feat, fix, docs, refactor, test, chore
- No Claude Code mentions in commits
- Concise and descriptive
