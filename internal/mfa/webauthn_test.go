package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ── Mocks ────────────────────────────────────────────────────────────────────

type mockWebAuthnCredRepo struct {
	createFn            func(ctx context.Context, cred *domain.WebAuthnCredential) error
	getByUserFn         func(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error)
	getByCredentialIDFn func(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error)
	updateSignCountFn   func(ctx context.Context, credentialID []byte, signCount uint32, cloneWarning bool) error
	deleteFn            func(ctx context.Context, id string) error
}

func (m *mockWebAuthnCredRepo) CreateCredential(ctx context.Context, cred *domain.WebAuthnCredential) error {
	if m.createFn != nil {
		return m.createFn(ctx, cred)
	}
	return nil
}

func (m *mockWebAuthnCredRepo) GetCredentialsByUser(ctx context.Context, _ uuid.UUID, userID string) ([]domain.WebAuthnCredential, error) {
	if m.getByUserFn != nil {
		return m.getByUserFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockWebAuthnCredRepo) GetCredentialByCredentialID(ctx context.Context, _ uuid.UUID, credentialID []byte) (*domain.WebAuthnCredential, error) {
	if m.getByCredentialIDFn != nil {
		return m.getByCredentialIDFn(ctx, credentialID)
	}
	return nil, storage.ErrNotFound
}

func (m *mockWebAuthnCredRepo) UpdateSignCount(ctx context.Context, _ uuid.UUID, credentialID []byte, signCount uint32, cloneWarning bool) error {
	if m.updateSignCountFn != nil {
		return m.updateSignCountFn(ctx, credentialID, signCount, cloneWarning)
	}
	return nil
}

func (m *mockWebAuthnCredRepo) DeleteCredential(ctx context.Context, _ uuid.UUID, id string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

type mockWebAuthnSessionStore struct {
	storeFn   func(ctx context.Context, userID, purpose string, data []byte) error
	consumeFn func(ctx context.Context, userID, purpose string) ([]byte, error)
}

func (m *mockWebAuthnSessionStore) StoreWebAuthnSession(ctx context.Context, userID, purpose string, data []byte) error {
	if m.storeFn != nil {
		return m.storeFn(ctx, userID, purpose, data)
	}
	return nil
}

func (m *mockWebAuthnSessionStore) ConsumeWebAuthnSession(ctx context.Context, userID, purpose string) ([]byte, error) {
	if m.consumeFn != nil {
		return m.consumeFn(ctx, userID, purpose)
	}
	return nil, storage.ErrNotFound
}

type mockWebAuthnProvider struct {
	beginRegistrationFn func(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	createCredentialFn  func(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error)
	beginLoginFn        func(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	validateLoginFn     func(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error)
}

func (m *mockWebAuthnProvider) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if m.beginRegistrationFn != nil {
		return m.beginRegistrationFn(user, opts...)
	}
	return &protocol.CredentialCreation{}, &webauthn.SessionData{Challenge: "test-challenge"}, nil
}

func (m *mockWebAuthnProvider) CreateCredential(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	if m.createCredentialFn != nil {
		return m.createCredentialFn(user, session, parsedResponse)
	}
	return &webauthn.Credential{
		ID:              []byte("new-cred-id"),
		PublicKey:       []byte("new-public-key"),
		AttestationType: "none",
		Authenticator:   webauthn.Authenticator{AAGUID: []byte("0123456789abcdef"), SignCount: 0},
	}, nil
}

func (m *mockWebAuthnProvider) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if m.beginLoginFn != nil {
		return m.beginLoginFn(user, opts...)
	}
	return &protocol.CredentialAssertion{}, &webauthn.SessionData{Challenge: "login-challenge"}, nil
}

func (m *mockWebAuthnProvider) ValidateLogin(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	if m.validateLoginFn != nil {
		return m.validateLoginFn(user, session, parsedResponse)
	}
	return nil, fmt.Errorf("not implemented")
}

// ── Test helpers ─────────────────────────────────────────────────────────────

func newTestWebAuthnService(
	provider *mockWebAuthnProvider,
	creds *mockWebAuthnCredRepo,
	sessions *mockWebAuthnSessionStore,
) *WebAuthnService {
	logger, _ := zap.NewDevelopment()
	return newWebAuthnServiceWithProvider(provider, creds, sessions, logger, audit.NopLogger{})
}

var testUser = &domain.User{
	ID:    "user-1",
	Email: "alice@example.com",
	Name:  "Alice",
}

func testCredential(id string, credID []byte, signCount uint32) domain.WebAuthnCredential {
	return domain.WebAuthnCredential{
		ID:              id,
		UserID:          "user-1",
		CredentialID:    credID,
		PublicKey:       []byte("pub-key-" + id),
		AttestationType: "none",
		AAGUID:          []byte("0123456789abcdef"),
		SignCount:       signCount,
		Name:            "Key " + id,
	}
}

// ── NewWebAuthnService Tests ─────────────────────────────────────────────────

func TestNewWebAuthnService_Success(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	svc, err := NewWebAuthnService(
		WebAuthnConfig{
			RPDisplayName: "QuantFlow Studio",
			RPID:          "example.com",
			RPOrigins:     []string{"https://example.com"},
		},
		&mockWebAuthnCredRepo{},
		&mockWebAuthnSessionStore{},
		logger,
		audit.NopLogger{},
	)
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestNewWebAuthnService_InvalidConfig(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	_, err := NewWebAuthnService(
		WebAuthnConfig{
			RPDisplayName: "Test",
			RPID:          "example.com",
			RPOrigins:     nil, // invalid: no origins
		},
		&mockWebAuthnCredRepo{},
		&mockWebAuthnSessionStore{},
		logger,
		audit.NopLogger{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configure webauthn relying party")
}

// ── BeginRegistration Tests ──────────────────────────────────────────────────

func TestBeginRegistration_Success(t *testing.T) {
	var storedSession []byte
	var storedPurpose string

	provider := &mockWebAuthnProvider{}
	creds := &mockWebAuthnCredRepo{}
	sessions := &mockWebAuthnSessionStore{
		storeFn: func(_ context.Context, _ string, purpose string, data []byte) error {
			storedSession = data
			storedPurpose = purpose
			return nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)
	creation, err := svc.BeginRegistration(context.Background(), testUser)
	require.NoError(t, err)
	require.NotNil(t, creation)
	assert.Equal(t, "registration", storedPurpose)
	assert.NotEmpty(t, storedSession)

	// Verify session data is valid JSON.
	var session webauthn.SessionData
	require.NoError(t, json.Unmarshal(storedSession, &session))
	assert.Equal(t, "test-challenge", session.Challenge)
}

func TestBeginRegistration_WithExistingCredentials(t *testing.T) {
	existingCred := testCredential("cred-1", []byte("existing-cred-id"), 5)

	var capturedUser webauthn.User
	provider := &mockWebAuthnProvider{
		beginRegistrationFn: func(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
			capturedUser = user
			return &protocol.CredentialCreation{}, &webauthn.SessionData{Challenge: "ch"}, nil
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{existingCred}, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, &mockWebAuthnSessionStore{})
	_, err := svc.BeginRegistration(context.Background(), testUser)
	require.NoError(t, err)

	// The user adapter should carry the existing credential.
	require.NotNil(t, capturedUser)
	assert.Len(t, capturedUser.WebAuthnCredentials(), 1)
	assert.Equal(t, []byte("existing-cred-id"), capturedUser.WebAuthnCredentials()[0].ID)
}

func TestBeginRegistration_GetCredentialsError(t *testing.T) {
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return nil, fmt.Errorf("db down")
		},
	}

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, creds, &mockWebAuthnSessionStore{})
	_, err := svc.BeginRegistration(context.Background(), testUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get existing credentials")
}

func TestBeginRegistration_StoreSessionError(t *testing.T) {
	sessions := &mockWebAuthnSessionStore{
		storeFn: func(_ context.Context, _, _ string, _ []byte) error {
			return fmt.Errorf("redis down")
		},
	}

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, &mockWebAuthnCredRepo{}, sessions)
	_, err := svc.BeginRegistration(context.Background(), testUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store registration session")
}

// ── FinishRegistration Tests ─────────────────────────────────────────────────

func TestFinishRegistration_Success(t *testing.T) {
	sessionData := webauthn.SessionData{Challenge: "test-challenge", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	var createdCred *domain.WebAuthnCredential
	creds := &mockWebAuthnCredRepo{
		createFn: func(_ context.Context, cred *domain.WebAuthnCredential) error {
			createdCred = cred
			return nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _ string, purpose string) ([]byte, error) {
			assert.Equal(t, "registration", purpose)
			return sessionBytes, nil
		},
	}
	provider := &mockWebAuthnProvider{}

	svc := newTestWebAuthnService(provider, creds, sessions)
	result, err := svc.FinishRegistration(context.Background(), testUser, "My YubiKey", nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "user-1", result.UserID)
	assert.Equal(t, "My YubiKey", result.Name)
	assert.Equal(t, []byte("new-cred-id"), result.CredentialID)
	assert.Equal(t, []byte("new-public-key"), result.PublicKey)
	assert.Equal(t, "none", result.AttestationType)
	assert.False(t, result.CloneWarning)

	require.NotNil(t, createdCred)
	assert.Equal(t, result.ID, createdCred.ID)
}

func TestFinishRegistration_NoSession(t *testing.T) {
	sessions := &mockWebAuthnSessionStore{} // default returns ErrNotFound
	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, &mockWebAuthnCredRepo{}, sessions)

	_, err := svc.FinishRegistration(context.Background(), testUser, "Key", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consume registration session")
}

func TestFinishRegistration_VerificationFailure(t *testing.T) {
	sessionData := webauthn.SessionData{Challenge: "ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	provider := &mockWebAuthnProvider{
		createCredentialFn: func(_ webauthn.User, _ webauthn.SessionData, _ *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
			return nil, fmt.Errorf("attestation verification failed")
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, _ string) ([]byte, error) {
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(provider, &mockWebAuthnCredRepo{}, sessions)
	_, err := svc.FinishRegistration(context.Background(), testUser, "Key", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify registration response")
}

func TestFinishRegistration_StoreCredentialError(t *testing.T) {
	sessionData := webauthn.SessionData{Challenge: "ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	creds := &mockWebAuthnCredRepo{
		createFn: func(_ context.Context, _ *domain.WebAuthnCredential) error {
			return fmt.Errorf("db error")
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, _ string) ([]byte, error) {
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, creds, sessions)
	_, err := svc.FinishRegistration(context.Background(), testUser, "Key", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store credential")
}

// ── BeginLogin Tests ─────────────────────────────────────────────────────────

func TestBeginLogin_Success(t *testing.T) {
	cred := testCredential("cred-1", []byte("cred-id-1"), 5)
	var storedPurpose string

	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred}, nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		storeFn: func(_ context.Context, _, purpose string, _ []byte) error {
			storedPurpose = purpose
			return nil
		},
	}

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, creds, sessions)
	assertion, err := svc.BeginLogin(context.Background(), testUser)
	require.NoError(t, err)
	require.NotNil(t, assertion)
	assert.Equal(t, "login", storedPurpose)
}

func TestBeginLogin_NoCredentials(t *testing.T) {
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return nil, nil // empty slice
		},
	}

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, creds, &mockWebAuthnSessionStore{})
	_, err := svc.BeginLogin(context.Background(), testUser)
	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrNotFound))
}

func TestBeginLogin_GetCredentialsError(t *testing.T) {
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return nil, fmt.Errorf("db error")
		},
	}

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, creds, &mockWebAuthnSessionStore{})
	_, err := svc.BeginLogin(context.Background(), testUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get credentials")
}

func TestBeginLogin_StoreSessionError(t *testing.T) {
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{testCredential("c1", []byte("id"), 0)}, nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		storeFn: func(_ context.Context, _, _ string, _ []byte) error {
			return fmt.Errorf("redis down")
		},
	}

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, creds, sessions)
	_, err := svc.BeginLogin(context.Background(), testUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store login session")
}

// ── FinishLogin Tests ────────────────────────────────────────────────────────

func TestFinishLogin_Success(t *testing.T) {
	credID := []byte("cred-id-1")
	cred := testCredential("cred-1", credID, 5)

	sessionData := webauthn.SessionData{Challenge: "login-ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	var updatedSignCount uint32
	var updatedCloneWarning bool

	provider := &mockWebAuthnProvider{
		validateLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
			return &webauthn.Credential{
				ID:        credID,
				PublicKey: []byte("pub-key-cred-1"),
				Authenticator: webauthn.Authenticator{
					SignCount:    6,
					CloneWarning: false,
				},
			}, nil
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred}, nil
		},
		updateSignCountFn: func(_ context.Context, _ []byte, sc uint32, cw bool) error {
			updatedSignCount = sc
			updatedCloneWarning = cw
			return nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, purpose string) ([]byte, error) {
			assert.Equal(t, "login", purpose)
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)
	result, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "cred-1", result.ID)
	assert.Equal(t, uint32(6), result.SignCount)
	assert.False(t, result.CloneWarning)
	assert.Equal(t, uint32(6), updatedSignCount)
	assert.False(t, updatedCloneWarning)
}

func TestFinishLogin_NoSession(t *testing.T) {
	sessions := &mockWebAuthnSessionStore{} // default returns ErrNotFound

	svc := newTestWebAuthnService(&mockWebAuthnProvider{}, &mockWebAuthnCredRepo{}, sessions)
	_, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "consume login session")
}

func TestFinishLogin_ValidationFailure(t *testing.T) {
	sessionData := webauthn.SessionData{Challenge: "ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	cred := testCredential("c1", []byte("id"), 0)
	provider := &mockWebAuthnProvider{
		validateLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
			return nil, fmt.Errorf("signature verification failed")
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred}, nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, _ string) ([]byte, error) {
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)
	_, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify login response")
}

// ── Registration Round-Trip Test ─────────────────────────────────────────────

func TestRegistrationRoundTrip(t *testing.T) {
	// Simulates begin + finish registration flow with mocked provider.
	var storedSessionData []byte

	provider := &mockWebAuthnProvider{
		beginRegistrationFn: func(user webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
			assert.Equal(t, []byte("user-1"), user.WebAuthnID())
			assert.Equal(t, "alice@example.com", user.WebAuthnName())
			return &protocol.CredentialCreation{}, &webauthn.SessionData{
				Challenge:      "reg-challenge-123",
				RelyingPartyID: "example.com",
				UserID:         user.WebAuthnID(),
			}, nil
		},
		createCredentialFn: func(user webauthn.User, session webauthn.SessionData, _ *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
			assert.Equal(t, "reg-challenge-123", session.Challenge)
			return &webauthn.Credential{
				ID:              []byte("brand-new-cred"),
				PublicKey:       []byte("brand-new-pk"),
				AttestationType: "packed",
				Authenticator: webauthn.Authenticator{
					AAGUID:    []byte("aaguid-1234abcd"),
					SignCount: 0,
				},
			}, nil
		},
	}

	var savedCred *domain.WebAuthnCredential
	creds := &mockWebAuthnCredRepo{
		createFn: func(_ context.Context, cred *domain.WebAuthnCredential) error {
			savedCred = cred
			return nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		storeFn: func(_ context.Context, _ string, _ string, data []byte) error {
			storedSessionData = data
			return nil
		},
		consumeFn: func(_ context.Context, _ string, _ string) ([]byte, error) {
			return storedSessionData, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)

	// Step 1: Begin registration.
	creation, err := svc.BeginRegistration(context.Background(), testUser)
	require.NoError(t, err)
	require.NotNil(t, creation)

	// Step 2: Finish registration (client response is mocked by provider).
	result, err := svc.FinishRegistration(context.Background(), testUser, "My Security Key", nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "user-1", result.UserID)
	assert.Equal(t, "My Security Key", result.Name)
	assert.Equal(t, []byte("brand-new-cred"), result.CredentialID)
	assert.Equal(t, []byte("brand-new-pk"), result.PublicKey)
	assert.Equal(t, "packed", result.AttestationType)
	assert.Equal(t, uint32(0), result.SignCount)

	require.NotNil(t, savedCred)
	assert.Equal(t, savedCred.ID, result.ID)
}

// ── Authentication Round-Trip Test ───────────────────────────────────────────

func TestAuthenticationRoundTrip(t *testing.T) {
	credID := []byte("existing-cred-id")
	existingCred := testCredential("cred-99", credID, 10)

	var storedSessionData []byte

	provider := &mockWebAuthnProvider{
		beginLoginFn: func(user webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
			assert.Equal(t, []byte("user-1"), user.WebAuthnID())
			assert.Len(t, user.WebAuthnCredentials(), 1)
			return &protocol.CredentialAssertion{}, &webauthn.SessionData{
				Challenge:      "login-challenge-456",
				RelyingPartyID: "example.com",
				UserID:         user.WebAuthnID(),
			}, nil
		},
		validateLoginFn: func(user webauthn.User, session webauthn.SessionData, _ *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
			assert.Equal(t, "login-challenge-456", session.Challenge)
			return &webauthn.Credential{
				ID:        credID,
				PublicKey: []byte("pub-key-cred-99"),
				Authenticator: webauthn.Authenticator{
					SignCount:    11, // incremented
					CloneWarning: false,
				},
			}, nil
		},
	}

	var updatedCredID []byte
	var updatedSC uint32
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{existingCred}, nil
		},
		updateSignCountFn: func(_ context.Context, cID []byte, sc uint32, _ bool) error {
			updatedCredID = cID
			updatedSC = sc
			return nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		storeFn: func(_ context.Context, _ string, _ string, data []byte) error {
			storedSessionData = data
			return nil
		},
		consumeFn: func(_ context.Context, _ string, _ string) ([]byte, error) {
			return storedSessionData, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)

	// Step 1: Begin login.
	assertion, err := svc.BeginLogin(context.Background(), testUser)
	require.NoError(t, err)
	require.NotNil(t, assertion)

	// Step 2: Finish login.
	result, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "cred-99", result.ID)
	assert.Equal(t, uint32(11), result.SignCount)
	assert.False(t, result.CloneWarning)
	assert.Equal(t, credID, updatedCredID)
	assert.Equal(t, uint32(11), updatedSC)
}

// ── Multiple Credentials Per User ────────────────────────────────────────────

func TestBeginLogin_MultipleCredentials(t *testing.T) {
	cred1 := testCredential("c1", []byte("cred-id-1"), 5)
	cred2 := testCredential("c2", []byte("cred-id-2"), 3)

	var capturedUser webauthn.User
	provider := &mockWebAuthnProvider{
		beginLoginFn: func(user webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
			capturedUser = user
			return &protocol.CredentialAssertion{}, &webauthn.SessionData{Challenge: "ch"}, nil
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred1, cred2}, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, &mockWebAuthnSessionStore{})
	_, err := svc.BeginLogin(context.Background(), testUser)
	require.NoError(t, err)

	require.NotNil(t, capturedUser)
	waCredentials := capturedUser.WebAuthnCredentials()
	assert.Len(t, waCredentials, 2)
	assert.Equal(t, []byte("cred-id-1"), waCredentials[0].ID)
	assert.Equal(t, []byte("cred-id-2"), waCredentials[1].ID)
}

func TestFinishLogin_SelectsCorrectCredential(t *testing.T) {
	credID1 := []byte("cred-id-1")
	credID2 := []byte("cred-id-2")
	cred1 := testCredential("c1", credID1, 5)
	cred2 := testCredential("c2", credID2, 3)

	sessionData := webauthn.SessionData{Challenge: "ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	// Provider validates and returns the second credential.
	provider := &mockWebAuthnProvider{
		validateLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
			return &webauthn.Credential{
				ID:        credID2,
				PublicKey: []byte("pub-key-c2"),
				Authenticator: webauthn.Authenticator{
					SignCount: 4,
				},
			}, nil
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred1, cred2}, nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, _ string) ([]byte, error) {
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)
	result, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.NoError(t, err)
	assert.Equal(t, "c2", result.ID)
	assert.Equal(t, uint32(4), result.SignCount)
}

// ── Sign-Count Validation Tests ──────────────────────────────────────────────

func TestFinishLogin_SignCountIncrement(t *testing.T) {
	credID := []byte("cred-id")
	cred := testCredential("c1", credID, 10)

	sessionData := webauthn.SessionData{Challenge: "ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	var savedSignCount uint32
	var savedCloneWarning bool

	provider := &mockWebAuthnProvider{
		validateLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
			return &webauthn.Credential{
				ID: credID,
				Authenticator: webauthn.Authenticator{
					SignCount:    15, // Normal increment
					CloneWarning: false,
				},
			}, nil
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred}, nil
		},
		updateSignCountFn: func(_ context.Context, _ []byte, sc uint32, cw bool) error {
			savedSignCount = sc
			savedCloneWarning = cw
			return nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, _ string) ([]byte, error) {
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)
	result, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.NoError(t, err)
	assert.Equal(t, uint32(15), savedSignCount)
	assert.False(t, savedCloneWarning)
	assert.Equal(t, uint32(15), result.SignCount)
	assert.False(t, result.CloneWarning)
}

func TestFinishLogin_CloneDetection(t *testing.T) {
	credID := []byte("cred-id")
	cred := testCredential("c1", credID, 10)

	sessionData := webauthn.SessionData{Challenge: "ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	var savedCloneWarning bool

	// Library sets CloneWarning when sign count regresses.
	provider := &mockWebAuthnProvider{
		validateLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
			return &webauthn.Credential{
				ID: credID,
				Authenticator: webauthn.Authenticator{
					SignCount:    8, // Regression: 8 < 10
					CloneWarning: true,
				},
			}, nil
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred}, nil
		},
		updateSignCountFn: func(_ context.Context, _ []byte, _ uint32, cw bool) error {
			savedCloneWarning = cw
			return nil
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, _ string) ([]byte, error) {
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)
	result, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.NoError(t, err)
	assert.True(t, savedCloneWarning)
	assert.True(t, result.CloneWarning)
}

func TestFinishLogin_UpdateSignCountErrorNonFatal(t *testing.T) {
	// Sign count update failure should not fail the login.
	credID := []byte("cred-id")
	cred := testCredential("c1", credID, 5)

	sessionData := webauthn.SessionData{Challenge: "ch", UserID: []byte("user-1")}
	sessionBytes, _ := json.Marshal(sessionData)

	provider := &mockWebAuthnProvider{
		validateLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
			return &webauthn.Credential{
				ID:            credID,
				Authenticator: webauthn.Authenticator{SignCount: 6},
			}, nil
		},
	}
	creds := &mockWebAuthnCredRepo{
		getByUserFn: func(_ context.Context, _ string) ([]domain.WebAuthnCredential, error) {
			return []domain.WebAuthnCredential{cred}, nil
		},
		updateSignCountFn: func(_ context.Context, _ []byte, _ uint32, _ bool) error {
			return fmt.Errorf("db write failed")
		},
	}
	sessions := &mockWebAuthnSessionStore{
		consumeFn: func(_ context.Context, _, _ string) ([]byte, error) {
			return sessionBytes, nil
		},
	}

	svc := newTestWebAuthnService(provider, creds, sessions)
	result, err := svc.FinishLogin(context.Background(), testUser, nil)
	require.NoError(t, err, "login should succeed even if sign count update fails")
	require.NotNil(t, result)
	assert.Equal(t, uint32(6), result.SignCount)
}

// ── webauthnUser Interface Tests ─────────────────────────────────────────────

func TestWebAuthnUser_Interface(t *testing.T) {
	creds := []webauthn.Credential{
		{ID: []byte("c1"), PublicKey: []byte("pk1")},
		{ID: []byte("c2"), PublicKey: []byte("pk2")},
	}

	u := &webauthnUser{
		id:          []byte("user-42"),
		name:        "test@example.com",
		displayName: "Test User",
		credentials: creds,
	}

	assert.Equal(t, []byte("user-42"), u.WebAuthnID())
	assert.Equal(t, "test@example.com", u.WebAuthnName())
	assert.Equal(t, "Test User", u.WebAuthnDisplayName())
	assert.Len(t, u.WebAuthnCredentials(), 2)
}

// ── toLibCredentials Tests ───────────────────────────────────────────────────

func TestToLibCredentials(t *testing.T) {
	domainCreds := []domain.WebAuthnCredential{
		{
			CredentialID:    []byte("cid-1"),
			PublicKey:       []byte("pk-1"),
			AttestationType: "packed",
			AAGUID:          []byte("aaguid-1"),
			SignCount:       42,
		},
		{
			CredentialID:    []byte("cid-2"),
			PublicKey:       []byte("pk-2"),
			AttestationType: "none",
			AAGUID:          []byte("aaguid-2"),
			SignCount:       0,
		},
	}

	result := toLibCredentials(domainCreds)
	require.Len(t, result, 2)

	assert.Equal(t, []byte("cid-1"), result[0].ID)
	assert.Equal(t, []byte("pk-1"), result[0].PublicKey)
	assert.Equal(t, "packed", result[0].AttestationType)
	assert.Equal(t, []byte("aaguid-1"), result[0].Authenticator.AAGUID)
	assert.Equal(t, uint32(42), result[0].Authenticator.SignCount)

	assert.Equal(t, []byte("cid-2"), result[1].ID)
	assert.Equal(t, uint32(0), result[1].Authenticator.SignCount)
}

func TestToLibCredentials_Empty(t *testing.T) {
	result := toLibCredentials(nil)
	assert.Len(t, result, 0)
}

// ── Sign-Count Logic (Authenticator.UpdateCounter) ───────────────────────────

func TestAuthenticatorUpdateCounter_Normal(t *testing.T) {
	auth := webauthn.Authenticator{SignCount: 5}
	auth.UpdateCounter(10)
	assert.Equal(t, uint32(10), auth.SignCount)
	assert.False(t, auth.CloneWarning)
}

func TestAuthenticatorUpdateCounter_CloneDetected(t *testing.T) {
	auth := webauthn.Authenticator{SignCount: 10}
	auth.UpdateCounter(5) // regression
	assert.True(t, auth.CloneWarning)
	assert.Equal(t, uint32(10), auth.SignCount, "sign count should not be updated on regression")
}

func TestAuthenticatorUpdateCounter_EqualNonZero(t *testing.T) {
	auth := webauthn.Authenticator{SignCount: 7}
	auth.UpdateCounter(7) // equal, non-zero
	assert.True(t, auth.CloneWarning)
}

func TestAuthenticatorUpdateCounter_BothZero(t *testing.T) {
	auth := webauthn.Authenticator{SignCount: 0}
	auth.UpdateCounter(0) // both zero = valid (authenticators that don't support counters)
	assert.False(t, auth.CloneWarning)
	assert.Equal(t, uint32(0), auth.SignCount)
}

// ── byteSliceEqual Tests ─────────────────────────────────────────────────────

func TestByteSliceEqual(t *testing.T) {
	assert.True(t, byteSliceEqual([]byte("abc"), []byte("abc")))
	assert.False(t, byteSliceEqual([]byte("abc"), []byte("abd")))
	assert.False(t, byteSliceEqual([]byte("abc"), []byte("ab")))
	assert.True(t, byteSliceEqual(nil, nil))
	assert.True(t, byteSliceEqual([]byte{}, []byte{}))
}
