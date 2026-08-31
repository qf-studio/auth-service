package e2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"
)

// suite is populated by TestMain before any test runs, unless -short was
// passed (see TestMain), in which case it stays nil and every test must
// skip itself via testing.Short() before touching it.
var suite *Env

// TestMain owns the container lifecycle for the whole package: one shared
// Postgres/Redis/SUT stack for every e2e test, torn down once after all
// tests finish. Under -short it skips container setup entirely so
// `go test -short ./...` never touches Docker.
func TestMain(m *testing.M) {
	// testing.Short() panics if called before flags are parsed, and TestMain
	// runs before that happens automatically, so parse explicitly here.
	flag.Parse()

	if testing.Short() {
		os.Exit(m.Run())
	}

	ctx := context.Background()
	env, teardown, err := setupSuite(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e suite setup failed: %v\n", err)
		teardown()
		os.Exit(1)
	}
	suite = env

	code := m.Run()
	teardown()
	os.Exit(code)
}
