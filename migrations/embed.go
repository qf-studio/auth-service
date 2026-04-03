// Package migrations embeds all SQL migration files so they can be used at
// runtime by the migrate CLI and integration tests without filesystem access.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
