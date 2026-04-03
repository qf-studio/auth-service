// Package migrations embeds all SQL migration files so they can be used at
// runtime by the migrate CLI and integration tests without filesystem access.
package migrations

import "embed"

//go:embed *.sql

// FS contains all SQL migration files embedded at compile time.
var FS embed.FS
