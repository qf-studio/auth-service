package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

// --- Mock implementations ---

type mockCredentialStore struct {
	cred *domain.AgentCredential
	err  error
}

func (m *mockCredentialStore) GetCredential(_ context.Context, _ string) (*domain.AgentCredential, error) {
	return m.cred, m.err
}

type mockProxyIssuer struct {
	token string
	err   error
}

func (m *mockProxyIssuer) IssueProxyToken(_ context.Context, _, _ string, _ []string, _ time.Duration) (string, error) {
	return m.token, m.err
}

type mockAccessChecker struct {
	allowed bool
	err     error
}

func (m *mockAccessChecker) CheckPermission(_ context.Context, _, _, _ string) (bool, error) {
	return m.allowed, m.err
}

// --- Helpers ---

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	v, err := NewVault("test-vault-secret")
	require.NoError(t, err)
	return v
}

func newTestCredential(t *testing.T, v *Vault, agentID uuid.UUID) *domain.AgentCredential {
	t.Helper()
	payload, err := v.Encrypt([]byte("secret-api-key-value"))
	require.NoError(t, err)
	return &domain.AgentCredential{
		ID:               uuid.New(),
		AgentClientID:    agentID,
		TargetService:    "payments-api",
		EncryptedPayload: payload,
		CredentialType:   domain.CredentialTypeAPIKey,
		Scopes:           []string{"payments:read", "payments:write"},
		Status:           domain.CredentialStatusActive,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
}

// --- Tests ---

func TestService_BrokerAccess_Success(t *testing.T) {
	vault := newTestVault(t)
	agentID := uuid.New()
	cred := newTestCredential(t, vault, agentID)

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{token: "qf_px_test-proxy-token"},
		&mockAccessChecker{allowed: true},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	result, err := svc.BrokerAccess(context.Background(), agentID.String(), cred.ID.String())
	require.NoError(t, err)
	assert.Equal(t, "qf_px_test-proxy-token", result.ProxyToken)
	assert.Equal(t, "payments-api", result.TargetService)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.WithinDuration(t, time.Now().Add(DefaultProxyTokenTTL), result.ExpiresAt, 2*time.Second)
}

func TestService_BrokerAccess_CredentialNotFound(t *testing.T) {
	vault := newTestVault(t)

	svc := NewService(
		&mockCredentialStore{cred: nil},
		&mockProxyIssuer{},
		&mockAccessChecker{},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), uuid.New().String(), uuid.New().String())
	assert.ErrorIs(t, err, domain.ErrCredentialNotFound)
}

func TestService_BrokerAccess_StorageError(t *testing.T) {
	vault := newTestVault(t)

	svc := NewService(
		&mockCredentialStore{err: errors.New("db connection lost")},
		&mockProxyIssuer{},
		&mockAccessChecker{},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), uuid.New().String(), uuid.New().String())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fetch credential")
}

func TestService_BrokerAccess_CredentialRevoked(t *testing.T) {
	vault := newTestVault(t)
	agentID := uuid.New()
	cred := newTestCredential(t, vault, agentID)
	cred.Status = domain.CredentialStatusRevoked

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{},
		&mockAccessChecker{},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), agentID.String(), cred.ID.String())
	assert.ErrorIs(t, err, domain.ErrCredentialRevoked)
}

func TestService_BrokerAccess_CredentialExpired(t *testing.T) {
	vault := newTestVault(t)
	agentID := uuid.New()
	cred := newTestCredential(t, vault, agentID)
	past := time.Now().Add(-1 * time.Hour)
	cred.ExpiresAt = &past

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{},
		&mockAccessChecker{},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), agentID.String(), cred.ID.String())
	assert.ErrorIs(t, err, domain.ErrCredentialExpired)
}

func TestService_BrokerAccess_NotOwner(t *testing.T) {
	vault := newTestVault(t)
	ownerID := uuid.New()
	otherAgentID := uuid.New()
	cred := newTestCredential(t, vault, ownerID)

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{},
		&mockAccessChecker{},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), otherAgentID.String(), cred.ID.String())
	assert.ErrorIs(t, err, domain.ErrBrokerAccessDenied)
}

func TestService_BrokerAccess_RBACDenied(t *testing.T) {
	vault := newTestVault(t)
	agentID := uuid.New()
	cred := newTestCredential(t, vault, agentID)

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{},
		&mockAccessChecker{allowed: false},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), agentID.String(), cred.ID.String())
	assert.ErrorIs(t, err, domain.ErrBrokerAccessDenied)
}

func TestService_BrokerAccess_RBACError(t *testing.T) {
	vault := newTestVault(t)
	agentID := uuid.New()
	cred := newTestCredential(t, vault, agentID)

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{},
		&mockAccessChecker{err: errors.New("rbac unavailable")},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), agentID.String(), cred.ID.String())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "check permission")
}

func TestService_BrokerAccess_DecryptionFailure(t *testing.T) {
	vault := newTestVault(t)
	agentID := uuid.New()
	cred := newTestCredential(t, vault, agentID)
	// Corrupt the encrypted payload.
	cred.EncryptedPayload = []byte("not-valid-ciphertext-but-long-enough-to-pass-length-check-xxxx")

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{},
		&mockAccessChecker{allowed: true},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), agentID.String(), cred.ID.String())
	assert.ErrorIs(t, err, domain.ErrDecryptionFailed)
}

func TestService_BrokerAccess_ProxyIssuerError(t *testing.T) {
	vault := newTestVault(t)
	agentID := uuid.New()
	cred := newTestCredential(t, vault, agentID)

	svc := NewService(
		&mockCredentialStore{cred: cred},
		&mockProxyIssuer{err: errors.New("signing key unavailable")},
		&mockAccessChecker{allowed: true},
		vault,
		zaptest.NewLogger(t),
		audit.NopLogger{},
	)

	_, err := svc.BrokerAccess(context.Background(), agentID.String(), cred.ID.String())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issue proxy token")
}
