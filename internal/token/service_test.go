package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

// mockClientAuthenticator implements ClientAuthenticator for tests.
type mockClientAuthenticator struct {
	client *domain.Client
	err    error
}

func (m *mockClientAuthenticator) AuthenticateClient(_ context.Context, _ uuid.UUID, _ string) (*domain.Client, error) {
	return m.client, m.err
}

// newTestService creates a Service with an in-memory ES256 key for testing.
func newTestService(t *testing.T, auth ClientAuthenticator) *Service {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return &Service{
		clients:    auth,
		signingKey: key,
		algorithm:  "ES256",
		logger:     zap.NewNop(),
	}
}

func TestClientCredentials_Success_ServiceType(t *testing.T) {
	clientID := uuid.New()
	mock := &mockClientAuthenticator{
		client: &domain.Client{
			ID:         clientID,
			Name:       "test-service",
			ClientType: domain.ClientTypeService,
			Scopes:     []string{"read", "write"},
			Status:     domain.ClientStatusActive,
		},
	}
	svc := newTestService(t, mock)

	result, err := svc.ClientCredentials(context.Background(), clientID.String(), "secret")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, int(defaultServiceTTL.Seconds()), result.ExpiresIn)
	assert.NotEmpty(t, result.AccessToken)
	assert.Empty(t, result.RefreshToken, "client_credentials must not issue refresh token")

	// Parse and verify claims.
	claims := parseTokenClaims(t, svc, result.AccessToken)
	assert.Equal(t, clientID.String(), claims["sub"])
	assert.Equal(t, "service", claims["client_type"])
	assert.Equal(t, "read write", claims["scope"])
	assert.Contains(t, claims["jti"], accessTokenPrefix)
}

func TestClientCredentials_Success_AgentType(t *testing.T) {
	clientID := uuid.New()
	mock := &mockClientAuthenticator{
		client: &domain.Client{
			ID:         clientID,
			Name:       "test-agent",
			ClientType: domain.ClientTypeAgent,
			Scopes:     []string{"read"},
			Status:     domain.ClientStatusActive,
		},
	}
	svc := newTestService(t, mock)

	result, err := svc.ClientCredentials(context.Background(), clientID.String(), "secret")
	require.NoError(t, err)

	assert.Equal(t, int(defaultAgentTTL.Seconds()), result.ExpiresIn)
	assert.Empty(t, result.RefreshToken)

	claims := parseTokenClaims(t, svc, result.AccessToken)
	assert.Equal(t, "agent", claims["client_type"])
}

func TestClientCredentials_CustomTTL(t *testing.T) {
	clientID := uuid.New()
	customTTL := 600 // 10 minutes
	mock := &mockClientAuthenticator{
		client: &domain.Client{
			ID:             clientID,
			Name:           "custom-ttl-service",
			ClientType:     domain.ClientTypeService,
			Scopes:         []string{"read"},
			AccessTokenTTL: customTTL,
			Status:         domain.ClientStatusActive,
		},
	}
	svc := newTestService(t, mock)

	result, err := svc.ClientCredentials(context.Background(), clientID.String(), "secret")
	require.NoError(t, err)
	assert.Equal(t, customTTL, result.ExpiresIn)
}

func TestClientCredentials_InvalidClientID(t *testing.T) {
	mock := &mockClientAuthenticator{}
	svc := newTestService(t, mock)

	_, err := svc.ClientCredentials(context.Background(), "not-a-uuid", "secret")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrUnauthorized))
}

func TestClientCredentials_AuthenticationFailure(t *testing.T) {
	mock := &mockClientAuthenticator{
		err: errors.New("invalid credentials"),
	}
	svc := newTestService(t, mock)

	_, err := svc.ClientCredentials(context.Background(), uuid.New().String(), "wrong-secret")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrUnauthorized))
}

func TestClientCredentials_NoRefreshToken(t *testing.T) {
	clientID := uuid.New()
	mock := &mockClientAuthenticator{
		client: &domain.Client{
			ID:         clientID,
			Name:       "no-refresh",
			ClientType: domain.ClientTypeService,
			Scopes:     []string{"read"},
			Status:     domain.ClientStatusActive,
		},
	}
	svc := newTestService(t, mock)

	result, err := svc.ClientCredentials(context.Background(), clientID.String(), "secret")
	require.NoError(t, err)
	assert.Empty(t, result.RefreshToken, "client_credentials grant MUST NOT return a refresh token")
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		allowed   []string
		wantErr   bool
	}{
		{
			name:      "all requested scopes allowed",
			requested: []string{"read", "write"},
			allowed:   []string{"read", "write", "admin"},
			wantErr:   false,
		},
		{
			name:      "empty requested scopes",
			requested: nil,
			allowed:   []string{"read"},
			wantErr:   false,
		},
		{
			name:      "scope not in allowed set",
			requested: []string{"read", "delete"},
			allowed:   []string{"read", "write"},
			wantErr:   true,
		},
		{
			name:      "all scopes invalid",
			requested: []string{"admin"},
			allowed:   []string{"read"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScopes(tt.requested, tt.allowed)
			if tt.wantErr {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, api.ErrForbidden))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClientTTL(t *testing.T) {
	tests := []struct {
		name     string
		client   *domain.Client
		expected time.Duration
	}{
		{
			name:     "service default",
			client:   &domain.Client{ClientType: domain.ClientTypeService},
			expected: defaultServiceTTL,
		},
		{
			name:     "agent default",
			client:   &domain.Client{ClientType: domain.ClientTypeAgent},
			expected: defaultAgentTTL,
		},
		{
			name:     "custom TTL overrides default",
			client:   &domain.Client{ClientType: domain.ClientTypeService, AccessTokenTTL: 600},
			expected: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, clientTTL(tt.client))
		})
	}
}

// parseTokenClaims parses a signed JWT and returns its claims.
func parseTokenClaims(t *testing.T, svc *Service, tokenString string) jwt.MapClaims {
	t.Helper()

	ecKey, ok := svc.signingKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	tok, err := jwt.Parse(tokenString, func(_ *jwt.Token) (interface{}, error) {
		return &ecKey.PublicKey, nil
	})
	require.NoError(t, err)
	require.True(t, tok.Valid)

	claims, ok := tok.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}
