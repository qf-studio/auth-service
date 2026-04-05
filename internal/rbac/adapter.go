package rbac

import (
	"context"
	"fmt"
	"strings"

	casbinmodel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// pgxAdapter implements the Casbin persist.Adapter interface backed by
// the casbin_rule PostgreSQL table accessed via a pgx connection pool.
type pgxAdapter struct {
	pool *pgxpool.Pool
	log  *zap.Logger
}

func newPgxAdapter(pool *pgxpool.Pool, log *zap.Logger) *pgxAdapter {
	return &pgxAdapter{pool: pool, log: log}
}

// LoadPolicy reads all rows from casbin_rule and populates the Casbin model.
func (a *pgxAdapter) LoadPolicy(m casbinmodel.Model) error {
	ctx := context.Background()

	rows, err := a.pool.Query(ctx,
		`SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rule ORDER BY id`)
	if err != nil {
		return fmt.Errorf("casbin load policy query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ptype, v0, v1, v2, v3, v4, v5 string
		if err := rows.Scan(&ptype, &v0, &v1, &v2, &v3, &v4, &v5); err != nil {
			return fmt.Errorf("casbin load policy scan: %w", err)
		}
		rule := buildLineFromParts(ptype, v0, v1, v2, v3, v4, v5)
		if err := persist.LoadPolicyLine(rule, m); err != nil {
			return fmt.Errorf("casbin load policy line: %w", err)
		}
	}

	return rows.Err()
}

// SavePolicy writes the entire model back to the database.
// It replaces all existing rows (delete + insert in a transaction).
func (a *pgxAdapter) SavePolicy(m casbinmodel.Model) error {
	ctx := context.Background()

	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("casbin save policy begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM casbin_rule`); err != nil {
		return fmt.Errorf("casbin save policy truncate: %w", err)
	}

	lines := policyLines(m)
	for _, line := range lines {
		if _, err := tx.Exec(ctx,
			`INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT DO NOTHING`,
			line[0], line[1], line[2], line[3], line[4], line[5], line[6]); err != nil {
			return fmt.Errorf("casbin save policy insert: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// AddPolicy inserts a single policy rule.
func (a *pgxAdapter) AddPolicy(sec, ptype string, rule []string) error {
	ctx := context.Background()
	parts := padRule(rule)
	_, err := a.pool.Exec(ctx,
		`INSERT INTO casbin_rule (ptype, v0, v1, v2, v3, v4, v5)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT DO NOTHING`,
		ptype, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
	if err != nil {
		return fmt.Errorf("casbin add policy: %w", err)
	}
	return nil
}

// RemovePolicy deletes a single policy rule.
func (a *pgxAdapter) RemovePolicy(sec, ptype string, rule []string) error {
	ctx := context.Background()
	parts := padRule(rule)
	_, err := a.pool.Exec(ctx,
		`DELETE FROM casbin_rule
		 WHERE ptype=$1 AND v0=$2 AND v1=$3 AND v2=$4 AND v3=$5 AND v4=$6 AND v5=$7`,
		ptype, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])
	if err != nil {
		return fmt.Errorf("casbin remove policy: %w", err)
	}
	return nil
}

// RemoveFilteredPolicy deletes policy rows matching the given field filter.
func (a *pgxAdapter) RemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx := context.Background()

	cols := []string{"v0", "v1", "v2", "v3", "v4", "v5"}
	conditions := []string{"ptype = $1"}
	args := []interface{}{ptype}
	idx := 2

	for i, val := range fieldValues {
		if val != "" {
			conditions = append(conditions, fmt.Sprintf("%s = $%d", cols[fieldIndex+i], idx))
			args = append(args, val)
			idx++
		}
	}

	query := fmt.Sprintf("DELETE FROM casbin_rule WHERE %s", strings.Join(conditions, " AND "))
	_, err := a.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("casbin remove filtered policy: %w", err)
	}
	return nil
}

// buildLineFromParts reconstructs the CSV policy line from individual column values.
func buildLineFromParts(ptype, v0, v1, v2, v3, v4, v5 string) string {
	parts := []string{ptype}
	for _, v := range []string{v0, v1, v2, v3, v4, v5} {
		if v == "" {
			break
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, ", ")
}

// padRule pads a rule slice to exactly 6 elements (v0–v5).
func padRule(rule []string) [6]string {
	var padded [6]string
	for i := 0; i < len(rule) && i < 6; i++ {
		padded[i] = rule[i]
	}
	return padded
}

// policyLines converts the Casbin model into rows for SavePolicy.
// Returns slices of [ptype, v0, v1, v2, v3, v4, v5].
// In Casbin's model map, the first key is the section ("p", "g"),
// and the second key is the policy type within that section.
func policyLines(m casbinmodel.Model) [][7]string {
	var lines [][7]string

	for _, assertions := range m {
		for ptype, assertion := range assertions {
			for _, rule := range assertion.Policy {
				parts := padRule(rule)
				lines = append(lines, [7]string{ptype, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]})
			}
		}
	}

	return lines
}
