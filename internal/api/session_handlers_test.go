package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock SessionService ---

type mockSessionService struct {
	createSessionFn     func(ctx context.Context, userID, ip, ua string) (*api.SessionInfo, error)
	listSessionsFn      func(ctx context.Context, userID string) ([]api.SessionInfo, error)
	deleteSessionFn     func(ctx context.Context, userID, sessionID string) error
	deleteAllSessionsFn func(ctx context.Context, userID string) error
}

func (m *mockSessionService) CreateSession(ctx context.Context, userID, ip, ua string) (*api.SessionInfo, error) {
	if m.createSessionFn != nil {
		return m.createSessionFn(ctx, userID, ip, ua)
	}
	return &api.SessionInfo{
		ID:             "sess-1",
		UserID:         userID,
		IPAddress:      ip,
		UserAgent:      ua,
		CreatedAt:      time.Now(),
		LastActivityAt: time.Now(),
	}, nil
}

func (m *mockSessionService) ListSessions(ctx context.Context, userID string) ([]api.SessionInfo, error) {
	if m.listSessionsFn != nil {
		return m.listSessionsFn(ctx, userID)
	}
	now := time.Now()
	return []api.SessionInfo{
		{ID: "sess-1", UserID: userID, IPAddress: "127.0.0.1", UserAgent: "TestAgent", CreatedAt: now, LastActivityAt: now},
	}, nil
}

func (m *mockSessionService) DeleteSession(ctx context.Context, userID, sessionID string) error {
	if m.deleteSessionFn != nil {
		return m.deleteSessionFn(ctx, userID, sessionID)
	}
	return nil
}

func (m *mockSessionService) DeleteAllSessions(ctx context.Context, userID string) error {
	if m.deleteAllSessionsFn != nil {
		return m.deleteAllSessionsFn(ctx, userID)
	}
	return nil
}

// newSessionTestRouter builds a public router with session support and a
// simple auth middleware that reads X-User-ID for testing.
func newSessionTestRouter(sessionSvc api.SessionService) *gin.Engine {
	authMW := func(c *gin.Context) {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing authentication")
			return
		}
		c.Set("user_id", userID)
		c.Next()
	}
	svc := &api.Services{
		Auth:    &mockAuthService{},
		Token:   &mockTokenService{},
		Session: sessionSvc,
	}
	mw := &api.MiddlewareStack{Auth: authMW}
	return api.NewPublicRouter(svc, mw, health.NewService())
}

// --- List Sessions ---

func TestListSessions_Success(t *testing.T) {
	r := newSessionTestRouter(&mockSessionService{})
	w := doRequest(r, http.MethodGet, "/auth/sessions", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.SessionList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Sessions, 1)
	assert.Equal(t, "sess-1", resp.Sessions[0].ID)
	assert.Equal(t, "user-42", resp.Sessions[0].UserID)
}

func TestListSessions_EmptyList(t *testing.T) {
	svc := &mockSessionService{
		listSessionsFn: func(_ context.Context, _ string) ([]api.SessionInfo, error) {
			return []api.SessionInfo{}, nil
		},
	}
	r := newSessionTestRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/sessions", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.SessionList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Sessions)
}

func TestListSessions_Unauthorized(t *testing.T) {
	r := newSessionTestRouter(&mockSessionService{})
	w := doRequest(r, http.MethodGet, "/auth/sessions", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListSessions_ServiceError(t *testing.T) {
	svc := &mockSessionService{
		listSessionsFn: func(_ context.Context, _ string) ([]api.SessionInfo, error) {
			return nil, fmt.Errorf("store unavailable: %w", api.ErrInternalError)
		},
	}
	r := newSessionTestRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/sessions", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Delete Session ---

func TestDeleteSession_Success(t *testing.T) {
	var capturedUserID, capturedSessionID string
	svc := &mockSessionService{
		deleteSessionFn: func(_ context.Context, userID, sessionID string) error {
			capturedUserID = userID
			capturedSessionID = sessionID
			return nil
		},
	}
	r := newSessionTestRouter(svc)
	w := doRequest(r, http.MethodDelete, "/auth/sessions/sess-99", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-42", capturedUserID)
	assert.Equal(t, "sess-99", capturedSessionID)
}

func TestDeleteSession_NotFound(t *testing.T) {
	svc := &mockSessionService{
		deleteSessionFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("session not found: %w", api.ErrNotFound)
		},
	}
	r := newSessionTestRouter(svc)
	w := doRequest(r, http.MethodDelete, "/auth/sessions/nonexistent", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteSession_Forbidden(t *testing.T) {
	svc := &mockSessionService{
		deleteSessionFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("session belongs to another user: %w", api.ErrForbidden)
		},
	}
	r := newSessionTestRouter(svc)
	w := doRequest(r, http.MethodDelete, "/auth/sessions/other-session", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDeleteSession_Unauthorized(t *testing.T) {
	r := newSessionTestRouter(&mockSessionService{})
	w := doRequest(r, http.MethodDelete, "/auth/sessions/sess-1", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Delete All Sessions ---

func TestDeleteAllSessions_Success(t *testing.T) {
	var capturedUserID string
	svc := &mockSessionService{
		deleteAllSessionsFn: func(_ context.Context, userID string) error {
			capturedUserID = userID
			return nil
		},
	}
	r := newSessionTestRouter(svc)
	w := doRequest(r, http.MethodDelete, "/auth/sessions", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-42", capturedUserID)
}

func TestDeleteAllSessions_ServiceError(t *testing.T) {
	svc := &mockSessionService{
		deleteAllSessionsFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("delete failed: %w", api.ErrInternalError)
		},
	}
	r := newSessionTestRouter(svc)
	w := doRequest(r, http.MethodDelete, "/auth/sessions", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteAllSessions_Unauthorized(t *testing.T) {
	r := newSessionTestRouter(&mockSessionService{})
	w := doRequest(r, http.MethodDelete, "/auth/sessions", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Login creates session ---

func TestLogin_CreatesSession(t *testing.T) {
	var sessionCreated bool
	sessionSvc := &mockSessionService{
		createSessionFn: func(_ context.Context, userID, _, _ string) (*api.SessionInfo, error) {
			sessionCreated = true
			assert.Equal(t, "user-1", userID)
			return &api.SessionInfo{ID: "sess-new", UserID: userID}, nil
		},
	}

	authSvc := &mockAuthService{
		loginFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_test",
				RefreshToken: "qf_rt_test",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				UserID:       "user-1",
			}, nil
		},
	}

	svc := &api.Services{
		Auth:    authSvc,
		Token:   &mockTokenService{},
		Session: sessionSvc,
	}
	router := api.NewPublicRouter(svc, nil, health.NewService())

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "super-secure-password-123",
	}
	w := doRequest(router, http.MethodPost, "/auth/login", body)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, sessionCreated, "session should have been created on login")
}

func TestLogin_SessionCreationFailure_DoesNotBlockLogin(t *testing.T) {
	sessionSvc := &mockSessionService{
		createSessionFn: func(_ context.Context, _, _, _ string) (*api.SessionInfo, error) {
			return nil, fmt.Errorf("session store unavailable")
		},
	}

	authSvc := &mockAuthService{
		loginFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_test",
				RefreshToken: "qf_rt_test",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				UserID:       "user-1",
			}, nil
		},
	}

	svc := &api.Services{
		Auth:    authSvc,
		Token:   &mockTokenService{},
		Session: sessionSvc,
	}
	router := api.NewPublicRouter(svc, nil, health.NewService())

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "super-secure-password-123",
	}
	w := doRequest(router, http.MethodPost, "/auth/login", body)

	// Login should succeed even if session creation fails.
	assert.Equal(t, http.StatusOK, w.Code)
}
