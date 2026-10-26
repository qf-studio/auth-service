package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/oidc"
	"github.com/qf-studio/auth-service/internal/storage"
)

// activeUserLookup resolves every subject to an active user.
func activeUserLookup() *fakeUserLookup {
	return &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			return &domain.User{ID: id}, nil
		},
	}
}

func newTestConsentService(t *testing.T, clients oidc.ClientLookup, grants oidc.ConsentGrantStore) (*oidc.ConsentService, oidc.Store) {
	t.Helper()
	return newTestConsentServiceWith(t, clients, activeUserLookup(), grants, audit.NopLogger{})
}

func newTestConsentServiceWith(t *testing.T, clients oidc.ClientLookup, users oidc.UserLookup, grants oidc.ConsentGrantStore, auditor audit.EventLogger) (*oidc.ConsentService, oidc.Store) {
	t.Helper()
	_, redisClient := newTestRedis(t)
	store := oidc.NewRedisStore(redisClient)
	svc := oidc.NewConsentService(testOIDCConfig(), store, clients, users, grants, zap.NewNop(), auditor)
	return svc, store
}

func seedLoginRequest(t *testing.T, store oidc.Store, lr *oidc.LoginRequest) {
	t.Helper()
	require.NoError(t, store.SaveLoginRequest(context.Background(), lr))
}

func seedConsentRequest(t *testing.T, store oidc.Store, cr *oidc.ConsentRequest) {
	t.Helper()
	require.NoError(t, store.SaveConsentRequest(context.Background(), cr))
}

// ────────────────────────────────────────────────────────────────────────────
// GetLoginRequest
// ────────────────────────────────────────────────────────────────────────────

func TestConsentService_GetLoginRequest_Success(t *testing.T) {
	svc, store := newTestConsentService(t, nil, nil)

	lr := &oidc.LoginRequest{
		Challenge:   "chal-1",
		ClientID:    uuid.New().String(),
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid", "profile"},
		State:       "state-1",
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedLoginRequest(t, store, lr)

	info, err := svc.GetLoginRequest(context.Background(), "chal-1")
	require.NoError(t, err)
	assert.Equal(t, "chal-1", info.Challenge)
	assert.Equal(t, lr.ClientID, info.ClientID)
	assert.Equal(t, "openid profile", info.Scope)
	assert.Contains(t, info.RequestURL, "/oauth/authorize?")

	// Non-destructive.
	_, err = svc.GetLoginRequest(context.Background(), "chal-1")
	require.NoError(t, err)
}

func TestConsentService_GetLoginRequest_NotFound(t *testing.T) {
	svc, _ := newTestConsentService(t, nil, nil)

	_, err := svc.GetLoginRequest(context.Background(), "missing")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// AcceptLogin
// ────────────────────────────────────────────────────────────────────────────

func TestConsentService_AcceptLogin_FirstPartyAutoConsent(t *testing.T) {
	client := &domain.Client{
		ID:           uuid.New(),
		ClientType:   domain.ClientTypeService,
		Owner:        "admin",
		Status:       domain.ClientStatusActive,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, id uuid.UUID) (*domain.Client, error) {
			require.Equal(t, client.ID, id)
			return client, nil
		},
	}
	svc, store := newTestConsentService(t, clients, &fakeConsentGrantStore{
		findActiveFn: func(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*domain.ConsentGrant, error) {
			t.Fatal("FindActive should not be called for first-party clients")
			return nil, nil
		},
	})

	lr := &oidc.LoginRequest{
		Challenge:   "chal-2",
		ClientID:    client.ID.String(),
		RedirectURI: client.RedirectURIs[0],
		Scopes:      []string{"openid"},
		State:       "state-2",
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedLoginRequest(t, store, lr)

	resp, err := svc.AcceptLogin(context.Background(), "chal-2", &api.AcceptLoginRequest{Subject: "user-1"})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.NotEmpty(t, u.Query().Get("code"))
	assert.Equal(t, "state-2", u.Query().Get("state"))

	// One-time use: consuming again should fail.
	_, err = svc.AcceptLogin(context.Background(), "chal-2", &api.AcceptLoginRequest{Subject: "user-1"})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestConsentService_AcceptLogin_ThirdPartyNoGrant_RedirectsToConsent(t *testing.T) {
	client := &domain.Client{
		ID:           uuid.New(),
		ClientType:   domain.ClientTypeService,
		Owner:        "third-party",
		Status:       domain.ClientStatusActive,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	grants := &fakeConsentGrantStore{
		findActiveFn: func(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*domain.ConsentGrant, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc, store := newTestConsentService(t, clients, grants)

	lr := &oidc.LoginRequest{
		Challenge:   "chal-3",
		ClientID:    client.ID.String(),
		RedirectURI: client.RedirectURIs[0],
		Scopes:      []string{"openid"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedLoginRequest(t, store, lr)

	resp, err := svc.AcceptLogin(context.Background(), "chal-3", &api.AcceptLoginRequest{Subject: "user-1"})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "login.example.com", u.Host)
	assert.NotEmpty(t, u.Query().Get("consent_challenge"))
	assert.Empty(t, u.Query().Get("code"))
}

func TestConsentService_AcceptLogin_ThirdPartyCoveringGrant_AutoConsent(t *testing.T) {
	client := &domain.Client{
		ID:           uuid.New(),
		ClientType:   domain.ClientTypeService,
		Owner:        "third-party",
		Status:       domain.ClientStatusActive,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	grants := &fakeConsentGrantStore{
		findActiveFn: func(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*domain.ConsentGrant, error) {
			return &domain.ConsentGrant{Scopes: []string{"openid", "profile"}}, nil
		},
	}
	svc, store := newTestConsentService(t, clients, grants)

	lr := &oidc.LoginRequest{
		Challenge:   "chal-4",
		ClientID:    client.ID.String(),
		RedirectURI: client.RedirectURIs[0],
		Scopes:      []string{"openid"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedLoginRequest(t, store, lr)

	resp, err := svc.AcceptLogin(context.Background(), "chal-4", &api.AcceptLoginRequest{Subject: "user-1"})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.NotEmpty(t, u.Query().Get("code"))
}

func TestConsentService_AcceptLogin_ThirdPartyNonCoveringGrant_RedirectsToConsent(t *testing.T) {
	client := &domain.Client{
		ID:           uuid.New(),
		ClientType:   domain.ClientTypeService,
		Owner:        "third-party",
		Status:       domain.ClientStatusActive,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	grants := &fakeConsentGrantStore{
		findActiveFn: func(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*domain.ConsentGrant, error) {
			return &domain.ConsentGrant{Scopes: []string{"profile"}}, nil
		},
	}
	svc, store := newTestConsentService(t, clients, grants)

	lr := &oidc.LoginRequest{
		Challenge:   "chal-5",
		ClientID:    client.ID.String(),
		RedirectURI: client.RedirectURIs[0],
		Scopes:      []string{"openid", "email"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedLoginRequest(t, store, lr)

	resp, err := svc.AcceptLogin(context.Background(), "chal-5", &api.AcceptLoginRequest{Subject: "user-1"})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.NotEmpty(t, u.Query().Get("consent_challenge"))
}

func firstPartyClientLookup(client *domain.Client) *fakeClientLookup {
	return &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
}

func seedFirstPartyLogin(t *testing.T, store oidc.Store, client *domain.Client, challenge string) {
	t.Helper()
	seedLoginRequest(t, store, &oidc.LoginRequest{
		Challenge:   challenge,
		ClientID:    client.ID.String(),
		RedirectURI: client.RedirectURIs[0],
		Scopes:      []string{"openid"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	})
}

func testFirstPartyClient() *domain.Client {
	return &domain.Client{
		ID:           uuid.New(),
		ClientType:   domain.ClientTypeService,
		Owner:        "admin",
		Status:       domain.ClientStatusActive,
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
}

func TestConsentService_AcceptLogin_SubjectChecks(t *testing.T) {
	deletedAt := time.Now().UTC()
	tests := []struct {
		name    string
		lookup  func(context.Context, uuid.UUID, string) (*domain.User, error)
		wantErr error
	}{
		{
			name: "unknown subject",
			lookup: func(context.Context, uuid.UUID, string) (*domain.User, error) {
				return nil, storage.ErrNotFound
			},
			wantErr: api.ErrNotFound,
		},
		{
			name: "locked subject",
			lookup: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
				return &domain.User{ID: id, Locked: true}, nil
			},
			wantErr: api.ErrForbidden,
		},
		{
			name: "deleted subject",
			lookup: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
				return &domain.User{ID: id, DeletedAt: &deletedAt}, nil
			},
			wantErr: api.ErrForbidden,
		},
		{
			name: "lookup failure",
			lookup: func(context.Context, uuid.UUID, string) (*domain.User, error) {
				return nil, errors.New("db down")
			},
			wantErr: api.ErrInternalError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testFirstPartyClient()
			rec := &recordingAuditor{}
			svc, store := newTestConsentServiceWith(t, firstPartyClientLookup(client), &fakeUserLookup{findByIDFn: tt.lookup}, nil, rec)
			seedFirstPartyLogin(t, store, client, "chal-subject")

			resp, err := svc.AcceptLogin(context.Background(), "chal-subject", &api.AcceptLoginRequest{Subject: "user-x"})
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Empty(t, rec.byType(audit.EventOIDCLoginAccept), "no accept event for a rejected subject")
		})
	}
}

func TestConsentService_AcceptLogin_InactiveClient(t *testing.T) {
	for _, status := range []string{domain.ClientStatusSuspended, domain.ClientStatusRevoked} {
		t.Run(status, func(t *testing.T) {
			client := testFirstPartyClient()
			client.Status = status
			svc, store := newTestConsentService(t, firstPartyClientLookup(client), nil)
			seedFirstPartyLogin(t, store, client, "chal-inactive")

			_, err := svc.AcceptLogin(context.Background(), "chal-inactive", &api.AcceptLoginRequest{Subject: "user-1"})
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrForbidden)
		})
	}
}

func TestConsentService_AcceptLogin_AuditsWithoutChallenge(t *testing.T) {
	client := testFirstPartyClient()
	rec := &recordingAuditor{}
	svc, store := newTestConsentServiceWith(t, firstPartyClientLookup(client), activeUserLookup(), nil, rec)
	const challenge = "chal-audit-secret"
	seedFirstPartyLogin(t, store, client, challenge)

	resp, err := svc.AcceptLogin(context.Background(), challenge, &api.AcceptLoginRequest{Subject: "user-1"})
	require.NoError(t, err)
	require.NotEmpty(t, resp.RedirectTo)

	events := rec.byType(audit.EventOIDCLoginAccept)
	require.Len(t, events, 1)
	ev := events[0]
	assert.Equal(t, "user-1", ev.ActorID)
	assert.Equal(t, client.ID.String(), ev.TargetID)
	assert.Equal(t, "true", ev.Metadata["consent_skipped"])
	sum := sha256.Sum256([]byte(challenge))
	assert.Equal(t, hex.EncodeToString(sum[:])[:8], ev.Metadata["challenge_ref"])
	assert.NotContains(t, fmt.Sprintf("%+v", ev), challenge)
}

func TestConsentService_AcceptLogin_ThirdPartyAuditsConsentNotSkipped(t *testing.T) {
	client := testFirstPartyClient()
	client.Owner = "third-party"
	rec := &recordingAuditor{}
	grants := &fakeConsentGrantStore{
		findActiveFn: func(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (*domain.ConsentGrant, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc, store := newTestConsentServiceWith(t, firstPartyClientLookup(client), activeUserLookup(), grants, rec)
	seedFirstPartyLogin(t, store, client, "chal-3p")

	_, err := svc.AcceptLogin(context.Background(), "chal-3p", &api.AcceptLoginRequest{Subject: "user-1"})
	require.NoError(t, err)

	events := rec.byType(audit.EventOIDCLoginAccept)
	require.Len(t, events, 1)
	assert.Equal(t, "false", events[0].Metadata["consent_skipped"])
}

func TestConsentService_AcceptLogin_NotFound(t *testing.T) {
	svc, _ := newTestConsentService(t, nil, nil)

	_, err := svc.AcceptLogin(context.Background(), "missing", &api.AcceptLoginRequest{Subject: "user-1"})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// RejectLogin
// ────────────────────────────────────────────────────────────────────────────

func TestConsentService_RejectLogin(t *testing.T) {
	rec := &recordingAuditor{}
	svc, store := newTestConsentServiceWith(t, nil, activeUserLookup(), nil, rec)

	lr := &oidc.LoginRequest{
		Challenge:   "chal-6",
		ClientID:    uuid.New().String(),
		RedirectURI: "https://app.example.com/callback",
		State:       "state-6",
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedLoginRequest(t, store, lr)

	resp, err := svc.RejectLogin(context.Background(), "chal-6", &api.RejectRequest{
		Error:            "access_denied",
		ErrorDescription: "user declined",
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", u.Query().Get("error"))
	assert.Equal(t, "state-6", u.Query().Get("state"))

	events := rec.byType(audit.EventOIDCLoginReject)
	require.Len(t, events, 1)
	assert.Equal(t, lr.ClientID, events[0].TargetID)
	assert.Equal(t, "access_denied", events[0].Metadata["error"])
	assert.NotEqual(t, "chal-6", events[0].Metadata["challenge_ref"])
	assert.Len(t, events[0].Metadata["challenge_ref"], 8)
}

// ────────────────────────────────────────────────────────────────────────────
// GetConsentRequest
// ────────────────────────────────────────────────────────────────────────────

func TestConsentService_GetConsentRequest_Success(t *testing.T) {
	svc, store := newTestConsentService(t, nil, nil)

	cr := &oidc.ConsentRequest{
		Challenge:   "cchal-1",
		Subject:     "user-1",
		ClientID:    uuid.New().String(),
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid", "profile"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedConsentRequest(t, store, cr)

	info, err := svc.GetConsentRequest(context.Background(), "cchal-1")
	require.NoError(t, err)
	assert.Equal(t, "cchal-1", info.Challenge)
	assert.Equal(t, cr.ClientID, info.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, info.RequestedScopes)
	assert.Equal(t, "user-1", info.Subject)
}

func TestConsentService_GetConsentRequest_NotFound(t *testing.T) {
	svc, _ := newTestConsentService(t, nil, nil)

	_, err := svc.GetConsentRequest(context.Background(), "missing")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// AcceptConsent
// ────────────────────────────────────────────────────────────────────────────

func TestConsentService_AcceptConsent_WithoutRemember_DoesNotPersistGrant(t *testing.T) {
	grants := &fakeConsentGrantStore{
		createFn: func(_ context.Context, _ *domain.ConsentGrant) (*domain.ConsentGrant, error) {
			t.Fatal("Create should not be called when Remember is false")
			return nil, nil
		},
	}
	svc, store := newTestConsentService(t, nil, grants)

	clientID := uuid.New()
	cr := &oidc.ConsentRequest{
		Challenge:   "cchal-2",
		Subject:     "user-1",
		ClientID:    clientID.String(),
		RedirectURI: "https://app.example.com/callback",
		State:       "state-c2",
		Scopes:      []string{"openid", "profile"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedConsentRequest(t, store, cr)

	resp, err := svc.AcceptConsent(context.Background(), "cchal-2", &api.AcceptConsentRequest{
		GrantedScopes: []string{"openid"},
		Remember:      false,
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.NotEmpty(t, u.Query().Get("code"))
	assert.Equal(t, "state-c2", u.Query().Get("state"))
}

func TestConsentService_AcceptConsent_WithRemember_PersistsGrant(t *testing.T) {
	clientID := uuid.New()
	var createdGrant *domain.ConsentGrant
	grants := &fakeConsentGrantStore{
		createFn: func(_ context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error) {
			createdGrant = grant
			return grant, nil
		},
	}
	svc, store := newTestConsentService(t, nil, grants)

	cr := &oidc.ConsentRequest{
		Challenge:   "cchal-3",
		Subject:     "user-1",
		ClientID:    clientID.String(),
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid", "profile", "email"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedConsentRequest(t, store, cr)

	resp, err := svc.AcceptConsent(context.Background(), "cchal-3", &api.AcceptConsentRequest{
		GrantedScopes: []string{"openid", "profile"},
		Remember:      true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.RedirectTo)

	require.NotNil(t, createdGrant)
	assert.Equal(t, "user-1", createdGrant.UserID)
	assert.Equal(t, clientID, createdGrant.ClientID)
	assert.Equal(t, []string{"openid", "profile"}, createdGrant.Scopes)
}

func TestConsentService_AcceptConsent_RejectsScopeNotOnRequest(t *testing.T) {
	grants := &fakeConsentGrantStore{
		createFn: func(_ context.Context, _ *domain.ConsentGrant) (*domain.ConsentGrant, error) {
			t.Fatal("no grant may be persisted for a rejected accept")
			return nil, nil
		},
	}
	svc, store := newTestConsentService(t, nil, grants)

	cr := &oidc.ConsentRequest{
		Challenge:   "cchal-escalate",
		Subject:     "user-1",
		ClientID:    uuid.New().String(),
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{"openid", "email"},
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedConsentRequest(t, store, cr)

	_, err := svc.AcceptConsent(context.Background(), "cchal-escalate", &api.AcceptConsentRequest{
		GrantedScopes: []string{"openid", "admin"},
		Remember:      true,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrBadRequest)

	// The rejected accept must not burn the consent request: a corrected
	// accept for a subset of the requested scopes still succeeds.
	resp, err := svc.AcceptConsent(context.Background(), "cchal-escalate", &api.AcceptConsentRequest{
		GrantedScopes: []string{"openid"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.RedirectTo)
}

func TestConsentService_AcceptConsent_NotFound(t *testing.T) {
	svc, _ := newTestConsentService(t, nil, nil)

	_, err := svc.AcceptConsent(context.Background(), "missing", &api.AcceptConsentRequest{GrantedScopes: []string{"openid"}})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// RejectConsent
// ────────────────────────────────────────────────────────────────────────────

func TestConsentService_RejectConsent(t *testing.T) {
	rec := &recordingAuditor{}
	svc, store := newTestConsentServiceWith(t, nil, activeUserLookup(), nil, rec)

	cr := &oidc.ConsentRequest{
		Challenge:   "cchal-4",
		Subject:     "user-1",
		ClientID:    uuid.New().String(),
		RedirectURI: "https://app.example.com/callback",
		State:       "state-c4",
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}
	seedConsentRequest(t, store, cr)

	resp, err := svc.RejectConsent(context.Background(), "cchal-4", &api.RejectRequest{
		Error: "access_denied",
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "access_denied", u.Query().Get("error"))
	assert.Equal(t, "state-c4", u.Query().Get("state"))

	events := rec.byType(audit.EventOIDCConsentReject)
	require.Len(t, events, 1)
	assert.Equal(t, "user-1", events[0].ActorID)
	assert.Equal(t, cr.ClientID, events[0].TargetID)
	assert.Equal(t, "access_denied", events[0].Metadata["error"])
	assert.NotEqual(t, "cchal-4", events[0].Metadata["challenge_ref"])
}
