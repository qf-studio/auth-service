//go:build integration

package testutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	testDBName   = "auth_test"
	testDBUser   = "test"
	testDBPass   = "test"
	postgresPort = "5432/tcp"
)

// PostgresContainer wraps a testcontainers PostgreSQL instance with a connection pool.
type PostgresContainer struct {
	Container testcontainers.Container
	Pool      *pgxpool.Pool
	DSN       string
}

// StartPostgres starts a PostgreSQL container and returns a connected pool.
// If migrationsDir is non-empty and the directory exists, migrations are applied automatically.
func StartPostgres(ctx context.Context, migrationsDir string) (*PostgresContainer, error) {
	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase(testDBName),
		postgres.WithUsername(testDBUser),
		postgres.WithPassword(testDBPass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("start postgres container: %w", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("get connection string: %w", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	pc := &PostgresContainer{
		Container: container,
		Pool:      pool,
		DSN:       dsn,
	}

	if migrationsDir != "" {
		if err := pc.RunMigrations(migrationsDir); err != nil {
			pc.Close(ctx)
			return nil, fmt.Errorf("run migrations: %w", err)
		}
	}

	return pc, nil
}

// RunMigrations applies all up migrations from the given directory.
func (pc *PostgresContainer) RunMigrations(migrationsDir string) error {
	absDir, err := filepath.Abs(migrationsDir)
	if err != nil {
		return fmt.Errorf("resolve migrations path: %w", err)
	}

	if _, err := os.Stat(absDir); os.IsNotExist(err) {
		return fmt.Errorf("migrations directory does not exist: %s", absDir)
	}

	// golang-migrate pgx/v5 driver uses pgx5:// scheme
	dbURL := pgxDSN(pc.DSN)

	m, err := migrate.New(
		"file://"+absDir,
		dbURL,
	)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() {
		_, _ = m.Close()
	}()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}

	return nil
}

// Close terminates the pool and container.
func (pc *PostgresContainer) Close(ctx context.Context) {
	if pc.Pool != nil {
		pc.Pool.Close()
	}
	if pc.Container != nil {
		_ = pc.Container.Terminate(ctx)
	}
}

// pgxDSN converts a postgres:// DSN to pgx5:// for the golang-migrate pgx/v5 driver.
func pgxDSN(dsn string) string {
	if len(dsn) > 11 && dsn[:11] == "postgres://" {
		return "pgx5://" + dsn[11:]
	}
	return dsn
}
