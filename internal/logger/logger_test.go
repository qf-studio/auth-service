package logger

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		wantErr     bool
		errContains string
	}{
		{
			name:        "production environment",
			environment: "production",
		},
		{
			name:        "staging environment",
			environment: "staging",
		},
		{
			name:        "development environment",
			environment: "development",
		},
		{
			name:        "invalid environment",
			environment: "invalid",
			wantErr:     true,
			errContains: "unsupported environment",
		},
		{
			name:        "empty environment",
			environment: "",
			wantErr:     true,
			errContains: "unsupported environment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetForTesting()

			err := Init(tt.environment)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				// GetLogger should return nop logger when Init fails.
				assert.NotNil(t, GetLogger())
				return
			}

			require.NoError(t, err)
			log := GetLogger()
			require.NotNil(t, log)
		})
	}
}

func TestInit_OnceSemantics(t *testing.T) {
	resetForTesting()

	require.NoError(t, Init("production"))
	log1 := GetLogger()

	// Second call is a no-op; the original logger is preserved.
	require.NoError(t, Init("development"))
	log2 := GetLogger()

	assert.Equal(t, log1, log2, "Init should only take effect once")
}

func TestGetLogger_BeforeInit(t *testing.T) {
	resetForTesting()

	log := GetLogger()
	require.NotNil(t, log, "GetLogger must never return nil")

	// Should be a no-op logger (core is a nopCore).
	assert.False(t, log.Core().Enabled(zapcore.DebugLevel))
}

func TestProductionConfig(t *testing.T) {
	resetForTesting()
	require.NoError(t, Init("production"))

	log := GetLogger()
	core := log.Core()

	// Production = InfoLevel: Debug disabled, Info enabled.
	assert.False(t, core.Enabled(zapcore.DebugLevel))
	assert.True(t, core.Enabled(zapcore.InfoLevel))
}

func TestDevelopmentConfig(t *testing.T) {
	resetForTesting()
	require.NoError(t, Init("development"))

	log := GetLogger()
	core := log.Core()

	// Development = DebugLevel.
	assert.True(t, core.Enabled(zapcore.DebugLevel))
	assert.True(t, core.Enabled(zapcore.InfoLevel))
}

func TestConvenienceFunctions(t *testing.T) {
	resetForTesting()

	// Replace the singleton with an observed logger so we can assert on output.
	observedCore, logs := observer.New(zapcore.DebugLevel)
	instance = zap.New(observedCore)
	// Mark once as done so Init won't overwrite.
	once.Do(func() {})

	Info("info message", zap.String("key", "val"))
	Error("error message")
	Debug("debug message")
	Warn("warn message")

	require.Equal(t, 4, logs.Len())

	assert.Equal(t, zapcore.InfoLevel, logs.All()[0].Level)
	assert.Equal(t, "info message", logs.All()[0].Message)
	assert.Equal(t, "val", logs.All()[0].ContextMap()["key"])

	assert.Equal(t, zapcore.ErrorLevel, logs.All()[1].Level)
	assert.Equal(t, "error message", logs.All()[1].Message)

	assert.Equal(t, zapcore.DebugLevel, logs.All()[2].Level)
	assert.Equal(t, "debug message", logs.All()[2].Message)

	assert.Equal(t, zapcore.WarnLevel, logs.All()[3].Level)
	assert.Equal(t, "warn message", logs.All()[3].Message)
}

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		wantErr     bool
		errContains string
		debugOn     bool
	}{
		{
			name:        "production returns JSON/Info logger",
			environment: "production",
			debugOn:     false,
		},
		{
			name:        "staging returns JSON/Info logger",
			environment: "staging",
			debugOn:     false,
		},
		{
			name:        "development returns console/Debug logger",
			environment: "development",
			debugOn:     true,
		},
		{
			name:        "invalid environment returns error",
			environment: "invalid",
			wantErr:     true,
			errContains: "unsupported environment",
		},
		{
			name:        "empty environment returns error",
			environment: "",
			wantErr:     true,
			errContains: "unsupported environment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := New(tt.environment)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, log)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, log)
			assert.Equal(t, tt.debugOn, log.Core().Enabled(zapcore.DebugLevel))
			assert.True(t, log.Core().Enabled(zapcore.InfoLevel))
		})
	}
}

func TestMustNew_Valid(t *testing.T) {
	assert.NotPanics(t, func() {
		log := MustNew("production")
		require.NotNil(t, log)
	})
}

func TestMustNew_Panics(t *testing.T) {
	assert.PanicsWithValue(t, `logger.MustNew: unsupported environment "bogus": must be development, staging, or production`, func() {
		MustNew("bogus")
	})
}

func TestConvenienceFunctions_BeforeInit(t *testing.T) {
	resetForTesting()

	// Should not panic even when Init hasn't been called.
	assert.NotPanics(t, func() {
		Info("should not panic")
		Error("should not panic")
		Debug("should not panic")
		Warn("should not panic")
	})
}
