package e2e

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// suite is populated by TestMain before any test runs, unless -short was
// passed (see TestMain), in which case it stays nil and every test must
// skip itself via testing.Short() before touching it.
var suite *Env

// TestMain owns test setup for the whole package. Three modes:
//
//   - `-short`: skips setup entirely (suite stays nil); every test must
//     guard itself via testing.Short(). `go test -short ./...` never
//     touches Docker or the network.
//   - SMOKE_BASE_URL set: wires suite directly to an already-running
//     deployment (see liveEnv) instead of booting testcontainers. This is
//     the auth-service-smoke image's mode (docker/Dockerfile.smoke,
//     GH-495) — only the TestSmoke* subset (smoke_test.go) is safe to run
//     this way; every other test in this package still assumes the
//     testcontainers-managed stack and will fail against a live URL.
//   - Otherwise: boots one shared Postgres/Redis/SUT stack via
//     testcontainers for every e2e test, torn down once after all tests
//     finish.
func TestMain(m *testing.M) {
	// testing.Short() panics if called before flags are parsed, and TestMain
	// runs before that happens automatically, so parse explicitly here.
	flag.Parse()

	if testing.Short() {
		os.Exit(m.Run())
	}

	if baseURL := os.Getenv("SMOKE_BASE_URL"); baseURL != "" {
		suite = liveEnv(baseURL)
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

// liveEnv builds an Env pointed at an already-running deployment from the
// SMOKE_* environment variables, in place of the testcontainers-managed
// stack setupSuite boots. AdminBaseURL and GRPCAddr are optional: the
// TestSmoke* tests skip the legs that need them (introspect, gRPC
// ValidateToken) when SMOKE_ADMIN_URL/SMOKE_GRPC_ADDR are unset.
func liveEnv(baseURL string) *Env {
	return &Env{
		PublicBaseURL: strings.TrimRight(baseURL, "/"),
		AdminBaseURL:  strings.TrimRight(os.Getenv("SMOKE_ADMIN_URL"), "/"),
		GRPCAddr:      os.Getenv("SMOKE_GRPC_ADDR"),
		HTTPClient:    &http.Client{Timeout: 15 * time.Second},
	}
}
