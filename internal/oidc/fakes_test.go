package oidc_test

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/api"
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
	issueTokenPairFn func(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error)
	issueIDTokenFn   func(ctx context.Context, subject, clientID, nonce string, authTime time.Time) (string, error)
}

func (f *fakeTokenIssuer) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error) {
	return f.issueTokenPairFn(ctx, subject, roles, scopes, clientType)
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
