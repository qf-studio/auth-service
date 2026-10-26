package oidc_test

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

// fakeClientLookup is a configurable fake for oidc.ClientLookup.
type fakeClientLookup struct {
	findByIDFn func(ctx context.Context, tenantID, id uuid.UUID) (*domain.Client, error)
}

func (f *fakeClientLookup) FindByID(ctx context.Context, tenantID, id uuid.UUID) (*domain.Client, error) {
	return f.findByIDFn(ctx, tenantID, id)
}

// fakeUserLookup is a configurable fake for oidc.UserLookup.
type fakeUserLookup struct {
	findByIDFn func(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)
}

func (f *fakeUserLookup) FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error) {
	return f.findByIDFn(ctx, tenantID, id)
}

// fakeTokenIssuer is a configurable fake for oidc.TokenIssuer.
type fakeTokenIssuer struct {
	issueTokenPairFn            func(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, audience ...string) (*api.AuthResult, error)
	issueTokenPairForClientFn   func(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, clientID string, audience ...string) (*api.AuthResult, error)
	issueAccessTokenForClientFn func(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, clientID string, audience ...string) (*api.AuthResult, error)
	issueIDTokenFn              func(ctx context.Context, subject, clientID, nonce string, authTime time.Time) (string, error)

	mu              sync.Mutex
	revokedJTIs     []string
	revokedFamilies []string
}

func (f *fakeTokenIssuer) RevokeJTI(_ context.Context, jti string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokedJTIs = append(f.revokedJTIs, jti)
	return nil
}

func (f *fakeTokenIssuer) RevokeRefreshFamily(_ context.Context, familyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokedFamilies = append(f.revokedFamilies, familyID)
	return nil
}

func (f *fakeTokenIssuer) revoked() (jtis, families []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revokedJTIs...), append([]string(nil), f.revokedFamilies...)
}

func (f *fakeTokenIssuer) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, audience ...string) (*api.AuthResult, error) {
	return f.issueTokenPairFn(ctx, subject, roles, scopes, clientType, audience...)
}

func (f *fakeTokenIssuer) IssueTokenPairForClient(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, clientID string, audience ...string) (*api.AuthResult, error) {
	if f.issueTokenPairForClientFn != nil {
		return f.issueTokenPairForClientFn(ctx, subject, roles, scopes, clientType, clientID, audience...)
	}
	return f.issueTokenPairFn(ctx, subject, roles, scopes, clientType, audience...)
}

func (f *fakeTokenIssuer) IssueAccessTokenForClient(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, clientID string, audience ...string) (*api.AuthResult, error) {
	if f.issueAccessTokenForClientFn != nil {
		return f.issueAccessTokenForClientFn(ctx, subject, roles, scopes, clientType, clientID, audience...)
	}
	res, err := f.issueTokenPairFn(ctx, subject, roles, scopes, clientType, audience...)
	if err != nil || res == nil {
		return res, err
	}
	out := *res
	out.RefreshToken = ""
	return &out, nil
}

func (f *fakeTokenIssuer) IssueIDToken(ctx context.Context, subject, clientID, nonce string, authTime time.Time) (string, error) {
	return f.issueIDTokenFn(ctx, subject, clientID, nonce, authTime)
}

// fakeConsentGrantStore is a configurable fake for oidc.ConsentGrantStore.
type fakeConsentGrantStore struct {
	findActiveFn func(ctx context.Context, tenantID uuid.UUID, userID string, clientID uuid.UUID) (*domain.ConsentGrant, error)
	createFn     func(ctx context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error)
}

func (f *fakeConsentGrantStore) FindActive(ctx context.Context, tenantID uuid.UUID, userID string, clientID uuid.UUID) (*domain.ConsentGrant, error) {
	return f.findActiveFn(ctx, tenantID, userID, clientID)
}

func (f *fakeConsentGrantStore) Create(ctx context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error) {
	return f.createFn(ctx, grant)
}

// fakeHasher is a configurable fake for password.Hasher, mirroring
// internal/admin's mockHasher.
type fakeHasher struct {
	hashFn   func(password string) (string, error)
	verifyFn func(password, hash string) (bool, error)
}

func (f *fakeHasher) Hash(password string) (string, error) {
	if f.hashFn != nil {
		return f.hashFn(password)
	}
	return "$argon2id$mock$" + password, nil
}

func (f *fakeHasher) Verify(password, hash string) (bool, error) {
	if f.verifyFn != nil {
		return f.verifyFn(password, hash)
	}
	return hash == "$argon2id$mock$"+password, nil
}

func (f *fakeHasher) NeedsUpgrade(_ string) bool { return false }

// recordingAuditor is an audit.EventLogger that keeps every event it sees.
type recordingAuditor struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingAuditor) LogEvent(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingAuditor) byType(typ string) []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []audit.Event
	for _, ev := range r.events {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}
