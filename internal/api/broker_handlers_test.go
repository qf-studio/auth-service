package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock BrokerTokenService ---

type mockBrokerTokenService struct {
	issueBrokerTokenFn func(ctx context.Context, clientID, clientSecret, targetName string) (*api.BrokerTokenResponse, error)
}

func (m *mockBrokerTokenService) IssueBrokerToken(ctx context.Context, clientID, clientSecret, targetName string) (*api.BrokerTokenResponse, error) {
	if m.issueBrokerTokenFn != nil {
		return m.issueBrokerTokenFn(ctx, clientID, clientSecret, targetName)
	}
	return &api.BrokerTokenResponse{
		AccessToken: "qf_at_broker_proxy_token",
		TokenType:   "Bearer",
		ExpiresIn:   300,
		TargetName:  targetName,
	}, nil
}

// --- Helper ---

func newBrokerRouter(brokerSvc api.BrokerTokenService) *gin.Engine {
	svc := &api.Services{
		Auth:   &mockAuthService{},
		Token:  &mockTokenService{},
		Broker: brokerSvc,
	}
	return api.NewPublicRouter(svc, nil, health.NewService())
}

// --- POST /auth/broker/token ---

func TestBrokerToken_Success(t *testing.T) {
	r := newBrokerRouter(&mockBrokerTokenService{})
	body := map[string]interface{}{
		"client_id":     "agent-client-id",
		"client_secret": "agent-client-secret",
		"target_name":   "openai",
	}
	w := doRequest(r, http.MethodPost, "/auth/broker/token", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.BrokerTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "qf_at_broker_proxy_token", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 300, resp.ExpiresIn)
	assert.Equal(t, "openai", resp.TargetName)
}

func TestBrokerToken_MissingFields(t *testing.T) {
	r := newBrokerRouter(&mockBrokerTokenService{})
	body := map[string]interface{}{
		"client_id": "agent-client-id",
	}
	w := doRequest(r, http.MethodPost, "/auth/broker/token", body)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBrokerToken_InvalidJSON(t *testing.T) {
	r := newBrokerRouter(&mockBrokerTokenService{})
	w := doRequest(r, http.MethodPost, "/auth/broker/token", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBrokerToken_Unauthorized(t *testing.T) {
	svc := &mockBrokerTokenService{
		issueBrokerTokenFn: func(_ context.Context, _, _, _ string) (*api.BrokerTokenResponse, error) {
			return nil, fmt.Errorf("invalid client credentials: %w", api.ErrUnauthorized)
		},
	}
	r := newBrokerRouter(svc)
	body := map[string]interface{}{
		"client_id":     "bad-client",
		"client_secret": "bad-secret",
		"target_name":   "openai",
	}
	w := doRequest(r, http.MethodPost, "/auth/broker/token", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBrokerToken_Forbidden(t *testing.T) {
	svc := &mockBrokerTokenService{
		issueBrokerTokenFn: func(_ context.Context, _, _, _ string) (*api.BrokerTokenResponse, error) {
			return nil, fmt.Errorf("not authorized for target: %w", api.ErrForbidden)
		},
	}
	r := newBrokerRouter(svc)
	body := map[string]interface{}{
		"client_id":     "agent-client-id",
		"client_secret": "agent-client-secret",
		"target_name":   "restricted-target",
	}
	w := doRequest(r, http.MethodPost, "/auth/broker/token", body)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestBrokerToken_NotRegistered(t *testing.T) {
	// When Broker is nil, the route should not be registered
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
	}
	r := api.NewPublicRouter(svc, nil, health.NewService())
	body := map[string]interface{}{
		"client_id":     "agent-client-id",
		"client_secret": "agent-client-secret",
		"target_name":   "openai",
	}
	w := doRequest(r, http.MethodPost, "/auth/broker/token", body)

	// Should be 404 because the route is not registered when Broker is nil
	assert.Equal(t, http.StatusNotFound, w.Code)
}
