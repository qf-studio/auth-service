//go:build integration

package testutil

import (
	"context"
	"os"
	"testing"
)

// Shared containers reused across all tests via TestMain.
var (
	testPG    *PostgresContainer
	testRedis *RedisContainer
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	var err error
	testPG, err = StartPostgres(ctx, "")
	if err != nil {
		panic("failed to start postgres: " + err.Error())
	}

	testRedis, err = StartRedis(ctx)
	if err != nil {
		testPG.Close(ctx)
		panic("failed to start redis: " + err.Error())
	}

	code := m.Run()

	testPG.Close(ctx)
	testRedis.Close(ctx)

	os.Exit(code)
}
