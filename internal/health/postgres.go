package health

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresChecker checks PostgreSQL connectivity by pinging the pool.
type PostgresChecker struct {
	pool *pgxpool.Pool
}

// NewPostgresChecker creates a checker for the given connection pool.
func NewPostgresChecker(pool *pgxpool.Pool) *PostgresChecker {
	return &PostgresChecker{pool: pool}
}

// Name returns the checker identifier.
func (c *PostgresChecker) Name() string { return "postgres" }

// Check pings the PostgreSQL pool and returns the result.
func (c *PostgresChecker) Check(ctx context.Context) Result {
	start := time.Now()
	if err := c.pool.Ping(ctx); err != nil {
		return Result{
			Status:   StatusUnhealthy,
			Message:  err.Error(),
			Duration: time.Since(start),
		}
	}
	return Result{
		Status:   StatusHealthy,
		Duration: time.Since(start),
	}
}
