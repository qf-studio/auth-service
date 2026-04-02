// Package logger provides a zap-based structured logger for the auth service.
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New creates a production-ready zap logger at the given log level.
// Returns an error if the level string is invalid.
func New(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", level, err)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)

	return cfg.Build()
}

// MustNew creates a logger using New and panics on error.
// Intended for use in main() where logger initialisation failure is fatal.
func MustNew(level string) *zap.Logger {
	l, err := New(level)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}
	return l
}
