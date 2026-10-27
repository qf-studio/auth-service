package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/secretbox"
)

// SecretEncryptionReport counts the rows sealed by EncryptExistingSecrets.
type SecretEncryptionReport struct {
	MFASecrets int
	Webhooks   int
}

// EncryptExistingSecrets seals every legacy plaintext TOTP secret and webhook
// signing secret in place (GH-531). It is idempotent: rows already in the
// "v1:" format are skipped, so it is safe to re-run or to run while the
// service is live (each update is a compare-and-set on the old value, so a
// concurrent write is never overwritten).
func EncryptExistingSecrets(ctx context.Context, pool *pgxpool.Pool, box *secretbox.Box) (SecretEncryptionReport, error) {
	var report SecretEncryptionReport
	if !box.Enabled() {
		return report, errors.New("encrypt existing secrets: no encryption key configured")
	}

	var err error
	if report.MFASecrets, err = sealColumn(ctx, pool, box, "mfa_secrets", "secret"); err != nil {
		return report, err
	}
	if report.Webhooks, err = sealColumn(ctx, pool, box, "webhooks", "secret_hash"); err != nil {
		return report, err
	}
	return report, nil
}

// sealColumn seals all plaintext values of table.column and returns how many
// rows it rewrote. table and column are package constants, never user input.
func sealColumn(ctx context.Context, pool *pgxpool.Pool, box *secretbox.Box, table, column string) (int, error) {
	// Rows are read fully before any update so no cursor is held open across
	// writes on the same pool.
	rows, err := pool.Query(ctx, fmt.Sprintf(
		`SELECT id::text, %[2]s FROM %[1]s WHERE %[2]s <> '' AND %[2]s NOT LIKE 'v1:%%'`, table, column))
	if err != nil {
		return 0, fmt.Errorf("list plaintext %s.%s: %w", table, column, err)
	}
	type row struct{ id, value string }
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.value); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan %s.%s: %w", table, column, err)
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate %s.%s: %w", table, column, err)
	}

	update := fmt.Sprintf(`UPDATE %[1]s SET %[2]s = $1 WHERE id::text = $2 AND %[2]s = $3`, table, column)
	sealed := 0
	for _, r := range pending {
		ct, err := box.Encrypt(r.value)
		if err != nil {
			return sealed, fmt.Errorf("encrypt %s.%s row %s: %w", table, column, r.id, err)
		}
		tag, err := pool.Exec(ctx, update, ct, r.id, r.value)
		if err != nil {
			return sealed, fmt.Errorf("update %s.%s row %s: %w", table, column, r.id, err)
		}
		sealed += int(tag.RowsAffected())
	}
	return sealed, nil
}
