// Package logger provides a zap-based structured singleton logger for the auth service.
// Call Init once at startup; then use the package-level convenience functions.
package logger

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	instance *zap.Logger
	once     sync.Once
)

// Init initializes the package-level singleton logger based on the environment.
//
//   - "production" / "staging": JSON encoder, InfoLevel, ISO 8601 timestamps.
//   - "development": console encoder, DebugLevel.
//
// Any other value returns an error without initializing the logger.
// Calling Init more than once is safe but has no effect after the first call.
func Init(environment string) error {
	var initErr error
	once.Do(func() {
		var cfg zap.Config
		switch environment {
		case "production", "staging":
			cfg = zap.NewProductionConfig()
			cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
			cfg.EncoderConfig.TimeKey = "timestamp"
			cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		case "development":
			cfg = zap.NewDevelopmentConfig()
			cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
			cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		default:
			initErr = fmt.Errorf("unsupported environment %q: must be development, staging, or production", environment)
			return
		}
		instance, initErr = cfg.Build()
	})
	return initErr
}

// GetLogger returns the singleton *zap.Logger.
// If Init has not been called, it returns a no-op logger so callers never get nil.
func GetLogger() *zap.Logger {
	if instance == nil {
		return zap.NewNop()
	}
	return instance
}

// Info logs a message at InfoLevel using the singleton logger.
func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

// Error logs a message at ErrorLevel using the singleton logger.
func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

// Debug logs a message at DebugLevel using the singleton logger.
func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

// Warn logs a message at WarnLevel using the singleton logger.
func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

// resetForTesting resets the singleton so Init can be called again in tests.
func resetForTesting() {
	instance = nil
	once = sync.Once{}
}
