//go:build integration

package testutil

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// defaultTables lists auth-service tables in truncation order (respects FK dependencies).
// This list should be updated as new migrations add tables.
var defaultTables = []string{
	"refresh_tokens",
	"access_tokens",
	"api_keys",
	"clients",
	"users",
}

// TruncateTables truncates the specified tables in a single TRUNCATE CASCADE statement.
// If no tables are specified, it truncates all known auth-service tables.
func TruncateTables(ctx context.Context, pool *pgxpool.Pool, tables ...string) error {
	if len(tables) == 0 {
		tables = defaultTables
	}

	existing, err := existingTables(ctx, pool, tables)
	if err != nil {
		return fmt.Errorf("check existing tables: %w", err)
	}

	if len(existing) == 0 {
		return nil
	}

	quoted := make([]string, len(existing))
	for i, t := range existing {
		quoted[i] = fmt.Sprintf("%q", t)
	}

	query := fmt.Sprintf("TRUNCATE TABLE %s CASCADE", strings.Join(quoted, ", "))
	_, err = pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("truncate tables: %w", err)
	}

	return nil
}

// existingTables filters the requested table names to only those that exist in the database.
func existingTables(ctx context.Context, pool *pgxpool.Pool, tables []string) ([]string, error) {
	rows, err := pool.Query(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = 'public'`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tableSet := make(map[string]struct{})
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tableSet[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var existing []string
	for _, t := range tables {
		if _, ok := tableSet[t]; ok {
			existing = append(existing, t)
		}
	}
	return existing, nil
}
