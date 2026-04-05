package rbac

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const tableName = "casbin_policies"

// dbExecer abstracts pgxpool.Pool and pgx.Tx for shared insert logic.
type dbExecer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// pgAdapter implements persist.FilteredAdapter backed by PostgreSQL via pgx.
type pgAdapter struct {
	pool       *pgxpool.Pool
	isFiltered bool
}

// NewPgAdapter creates a Casbin adapter that stores policies in PostgreSQL.
func NewPgAdapter(pool *pgxpool.Pool) persist.FilteredAdapter {
	return &pgAdapter{pool: pool}
}

// LoadPolicy loads all policies from the database into the Casbin model.
func (a *pgAdapter) LoadPolicy(m model.Model) error {
	a.isFiltered = false
	return a.loadRows(context.Background(), m, "", nil)
}

// LoadFilteredPolicy loads only the policies matching the filter.
// The filter must be a *PolicyFilter.
func (a *pgAdapter) LoadFilteredPolicy(m model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(m)
	}
	pf, ok := filter.(*PolicyFilter)
	if !ok {
		return fmt.Errorf("rbac adapter: invalid filter type %T", filter)
	}
	clause, args := pf.toWhereClause()
	a.isFiltered = true
	return a.loadRows(context.Background(), m, clause, args)
}

// IsFiltered returns true if the last policy load was filtered.
func (a *pgAdapter) IsFiltered() bool {
	return a.isFiltered
}

// SavePolicy persists the full model policy to the database, replacing all rows.
func (a *pgAdapter) SavePolicy(m model.Model) error {
	ctx := context.Background()
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rbac adapter: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort on defer

	if _, err = tx.Exec(ctx, "DELETE FROM "+tableName); err != nil {
		return fmt.Errorf("rbac adapter: truncate: %w", err)
	}

	for ptype, ast := range m["p"] {
		for _, rule := range ast.Policy {
			if err := insertRow(ctx, tx, ptype, rule); err != nil {
				return err
			}
		}
	}
	for ptype, ast := range m["g"] {
		for _, rule := range ast.Policy {
			if err := insertRow(ctx, tx, ptype, rule); err != nil {
				return err
			}
		}
	}

	return tx.Commit(ctx)
}

// AddPolicy adds a single policy rule to the database.
func (a *pgAdapter) AddPolicy(_ string, ptype string, rule []string) error {
	return insertRow(context.Background(), a.pool, ptype, rule)
}

// RemovePolicy removes a single policy rule from the database.
func (a *pgAdapter) RemovePolicy(_ string, ptype string, rule []string) error {
	ctx := context.Background()
	where, args := ruleToWhere(ptype, rule)
	q := "DELETE FROM " + tableName + " WHERE " + where
	if _, err := a.pool.Exec(ctx, q, args...); err != nil {
		return fmt.Errorf("rbac adapter: remove policy: %w", err)
	}
	return nil
}

// RemoveFilteredPolicy removes policies matching the given field filter.
func (a *pgAdapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx := context.Background()
	where := "ptype = $1"
	args := []any{ptype}
	idx := 2

	for i, v := range fieldValues {
		if v == "" {
			continue
		}
		col := fmt.Sprintf("v%d", fieldIndex+i)
		where += fmt.Sprintf(" AND %s = $%d", col, idx)
		args = append(args, v)
		idx++
	}

	q := "DELETE FROM " + tableName + " WHERE " + where
	if _, err := a.pool.Exec(ctx, q, args...); err != nil {
		return fmt.Errorf("rbac adapter: remove filtered policy: %w", err)
	}
	return nil
}

// PolicyFilter defines criteria for filtered policy loading.
type PolicyFilter struct {
	PType string
	V0    string
	V1    string
	V2    string
}

// toWhereClause builds a parameterized WHERE clause from the filter fields.
func (f *PolicyFilter) toWhereClause() (string, []any) {
	var parts []string
	var args []any
	idx := 1

	for _, pair := range []struct{ col, val string }{
		{"ptype", f.PType},
		{"v0", f.V0},
		{"v1", f.V1},
		{"v2", f.V2},
	} {
		if pair.val == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s = $%d", pair.col, idx))
		args = append(args, pair.val)
		idx++
	}
	if len(parts) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(parts, " AND "), args
}

// loadRows queries the policy table and loads results into the model.
func (a *pgAdapter) loadRows(ctx context.Context, m model.Model, whereClause string, args []any) error {
	q := "SELECT ptype, v0, v1, v2, v3, v4, v5 FROM " + tableName + whereClause
	rows, err := a.pool.Query(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("rbac adapter: query policies: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ptype, v0, v1, v2, v3, v4, v5 string
		if err := rows.Scan(&ptype, &v0, &v1, &v2, &v3, &v4, &v5); err != nil {
			return fmt.Errorf("rbac adapter: scan row: %w", err)
		}
		rule := trimEmpty([]string{v0, v1, v2, v3, v4, v5})
		persist.LoadPolicyLine(fmt.Sprintf("%s, %s", ptype, strings.Join(rule, ", ")), m)
	}
	return rows.Err()
}

// insertRow inserts a single policy rule row.
func insertRow(ctx context.Context, db dbExecer, ptype string, rule []string) error {
	vals := pad6(rule)
	q := "INSERT INTO " + tableName + " (ptype, v0, v1, v2, v3, v4, v5) VALUES ($1, $2, $3, $4, $5, $6, $7)"
	if _, err := db.Exec(ctx, q, ptype, vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]); err != nil {
		return fmt.Errorf("rbac adapter: insert policy: %w", err)
	}
	return nil
}

// ruleToWhere builds a WHERE clause matching a specific policy rule.
func ruleToWhere(ptype string, rule []string) (string, []any) {
	vals := pad6(rule)
	where := "ptype = $1 AND v0 = $2 AND v1 = $3 AND v2 = $4 AND v3 = $5 AND v4 = $6 AND v5 = $7"
	args := []any{ptype, vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]}
	return where, args
}

// pad6 pads a string slice to exactly 6 elements with empty strings.
func pad6(rule []string) []string {
	out := make([]string, 6)
	copy(out, rule)
	return out
}

// trimEmpty removes trailing empty strings from a slice.
func trimEmpty(s []string) []string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != "" {
			return s[:i+1]
		}
	}
	return nil
}

// Compile-time check: pgx.Tx must satisfy dbExecer.
var _ dbExecer = (pgx.Tx)(nil)
