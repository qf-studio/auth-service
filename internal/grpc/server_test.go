package grpc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
)

func testConfig() config.GRPCConfig {
	return config.GRPCConfig{
		Port:                  0, // random port
		KeepaliveTime:         2 * time.Hour,
		KeepaliveTimeout:      20 * time.Second,
		MaxConnectionIdle:     5 * time.Minute,
		MaxConnectionAge:      30 * time.Minute,
		MaxConnectionAgeGrace: 10 * time.Second,
	}
}

func TestNew_NoTLS(t *testing.T) {
	srv, err := New(testConfig(), Deps{Logger: zap.NewNop()})
	require.NoError(t, err)
	assert.NotNil(t, srv)
	assert.NotNil(t, srv.GRPCServer())
}

func TestNew_InvalidTLS(t *testing.T) {
	cfg := testConfig()
	cfg.TLSCertPath = "/nonexistent/cert.pem"
	cfg.TLSKeyPath = "/nonexistent/key.pem"

	_, err := New(cfg, Deps{Logger: zap.NewNop()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "grpc tls")
}

func TestStartAndClose(t *testing.T) {
	srv, err := New(testConfig(), Deps{Logger: zap.NewNop()})
	require.NoError(t, err)

	err = srv.Start()
	require.NoError(t, err)
	assert.NotNil(t, srv.listener)

	err = srv.Close()
	require.NoError(t, err)
}

func TestName(t *testing.T) {
	srv, err := New(testConfig(), Deps{Logger: zap.NewNop()})
	require.NoError(t, err)
	assert.Equal(t, "grpc", srv.Name())
}
