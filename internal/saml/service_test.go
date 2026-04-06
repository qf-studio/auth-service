package saml

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

// --- Mock IdP response generator ---

// mockIdPResponse builds a base64-encoded SAML response XML for testing.
func mockIdPResponse(t *testing.T, opts ...mockResponseOption) string {
	t.Helper()
	cfg := defaultMockResponse()
	for _, opt := range opts {
		opt(&cfg)
	}

	resp := buildSAMLResponseXML(cfg)
	raw, err := xml.Marshal(resp)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

type mockResponseConfig struct {
	idpEntityID  string
	nameID       string
	nameIDFormat string
	email        string
	name         string
	groups       []string
	sessionIndex string
	inResponseTo string
	statusCode   string
	notBefore    time.Time
	notOnOrAfter time.Time
	noAssertion  bool
}

type mockResponseOption func(*mockResponseConfig)

func defaultMockResponse() mockResponseConfig {
	now := time.Now().UTC()
	return mockResponseConfig{
		idpEntityID:  "https://idp.example.com",
		nameID:       "user@example.com",
		nameIDFormat: NameIDFormatEmailAddress,
		email:        "user@example.com",
		name:         "Test User",
		groups:       []string{"engineering"},
		sessionIndex: "_session_123",
		inResponseTo: "",
		statusCode:   "urn:oasis:names:tc:SAML:2.0:status:Success",
		notBefore:    now.Add(-5 * time.Minute),
		notOnOrAfter: now.Add(5 * time.Minute),
	}
}

func withIdPEntityID(id string) mockResponseOption {
	return func(c *mockResponseConfig) { c.idpEntityID = id }
}

func withNameID(id, format string) mockResponseOption {
	return func(c *mockResponseConfig) {
		c.nameID = id
		c.nameIDFormat = format
	}
}

func withEmail(email string) mockResponseOption {
	return func(c *mockResponseConfig) { c.email = email }
}

func withName(name string) mockResponseOption {
	return func(c *mockResponseConfig) { c.name = name }
}

func withGroups(groups ...string) mockResponseOption {
	return func(c *mockResponseConfig) { c.groups = groups }
}

func withInResponseTo(id string) mockResponseOption {
	return func(c *mockResponseConfig) { c.inResponseTo = id }
}

func withStatusCode(code string) mockResponseOption {
	return func(c *mockResponseConfig) { c.statusCode = code }
}

func withNotBefore(t time.Time) mockResponseOption {
	return func(c *mockResponseConfig) { c.notBefore = t }
}

func withNotOnOrAfter(t time.Time) mockResponseOption {
	return func(c *mockResponseConfig) { c.notOnOrAfter = t }
}

func withNoAssertion() mockResponseOption {
	return func(c *mockResponseConfig) { c.noAssertion = true }
}

func buildSAMLResponseXML(cfg mockResponseConfig) samlResponse {
	resp := samlResponse{
		ID:           "_resp_" + generateSAMLID(),
		InResponseTo: cfg.inResponseTo,
		Destination:  "https://sp.example.com/saml/acs",
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		Issuer:       cfg.idpEntityID,
		Status: samlStatus{
			StatusCode: samlStatusCode{Value: cfg.statusCode},
		},
	}

	if cfg.noAssertion {
		return resp
	}

	attrs := []samlAttribute{
		{Name: AttrEmailFriendly, Values: []samlAttrValue{{Value: cfg.email}}},
		{Name: AttrDisplayName, Values: []samlAttrValue{{Value: cfg.name}}},
	}
	if len(cfg.groups) > 0 {
		groupVals := make([]samlAttrValue, 0, len(cfg.groups))
		for _, g := range cfg.groups {
			groupVals = append(groupVals, samlAttrValue{Value: g})
		}
		attrs = append(attrs, samlAttribute{Name: AttrGroupsFriendly, Values: groupVals})
	}

	assertion := samlAssertion{
		ID:     "_assertion_" + generateSAMLID(),
		Issuer: cfg.idpEntityID,
		Subject: samlSubject{
			NameID: samlNameID{
				Format: cfg.nameIDFormat,
				Value:  cfg.nameID,
			},
			SubjectConfirmation: samlSubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				Data: samlSubjectConfirmationData{
					InResponseTo: cfg.inResponseTo,
					Recipient:    "https://sp.example.com/saml/acs",
					NotOnOrAfter: cfg.notOnOrAfter.Format(time.RFC3339),
				},
			},
		},
		Conditions: samlConditions{
			NotBefore:    cfg.notBefore.Format(time.RFC3339),
			NotOnOrAfter: cfg.notOnOrAfter.Format(time.RFC3339),
		},
		AuthnStatements: []samlAuthnStatement{
			{SessionIndex: cfg.sessionIndex},
		},
		AttributeStatements: []samlAttributeStatement{
			{Attributes: attrs},
		},
	}

	resp.Assertions = []samlAssertion{assertion}
	return resp
}

// --- Mock token issuer ---

type mockTokenIssuer struct {
	IssueTokenPairFn func(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error)
}

func (m *mockTokenIssuer) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error) {
	if m.IssueTokenPairFn != nil {
		return m.IssueTokenPairFn(ctx, subject, roles, scopes, clientType)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_test_access",
		RefreshToken: "qf_rt_test_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		UserID:       subject,
	}, nil
}

// --- Mock refresh token repository ---

type mockRefreshTokenRepo struct {
	StoreFn func(ctx context.Context, signature, userID string, expiresAt time.Time) error
}

func (m *mockRefreshTokenRepo) Store(ctx context.Context, signature, userID string, expiresAt time.Time) error {
	if m.StoreFn != nil {
		return m.StoreFn(ctx, signature, userID, expiresAt)
	}
	return nil
}

func (m *mockRefreshTokenRepo) FindBySignature(_ context.Context, _ string) (*domain.RefreshTokenRecord, error) {
	return nil, storage.ErrNotFound
}

func (m *mockRefreshTokenRepo) Revoke(_ context.Context, _ string) error {
	return nil
}

func (m *mockRefreshTokenRepo) RevokeAllForUser(_ context.Context, _ string) error {
	return nil
}

// --- Tests ---

func TestGenerateMetadata(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SPConfig
		wantErr bool
		check   func(t *testing.T, data []byte)
	}{
		{
			name: "valid metadata",
			cfg: SPConfig{
				EntityID:             "https://sp.example.com",
				ACSURL:               "https://sp.example.com/saml/acs",
				WantAssertionsSigned: true,
			},
			check: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "https://sp.example.com")
				assert.Contains(t, string(data), "https://sp.example.com/saml/acs")
				assert.Contains(t, string(data), NameIDFormatPersistent)
				assert.Contains(t, string(data), "<?xml version=")
			},
		},
		{
			name: "custom NameID format",
			cfg: SPConfig{
				EntityID:     "https://sp.example.com",
				ACSURL:       "https://sp.example.com/saml/acs",
				NameIDFormat: NameIDFormatEmailAddress,
			},
			check: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), NameIDFormatEmailAddress)
			},
		},
		{
			name: "missing entity ID",
			cfg: SPConfig{
				ACSURL: "https://sp.example.com/saml/acs",
			},
			wantErr: true,
		},
		{
			name: "missing ACS URL",
			cfg: SPConfig{
				EntityID: "https://sp.example.com",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := GenerateMetadata(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, data)
			}
		})
	}
}

func TestBuildAuthnRequest(t *testing.T) {
	sp := SPConfig{
		EntityID: "https://sp.example.com",
		ACSURL:   "https://sp.example.com/saml/acs",
	}

	tests := []struct {
		name    string
		sp      SPConfig
		idp     IdPConfig
		wantErr bool
		check   func(t *testing.T, redirectURL, requestID string)
	}{
		{
			name: "valid request",
			sp:   sp,
			idp: IdPConfig{
				EntityID: "https://idp.example.com",
				SSOURL:   "https://idp.example.com/sso",
			},
			check: func(t *testing.T, redirectURL, requestID string) {
				assert.Contains(t, redirectURL, "https://idp.example.com/sso")
				assert.Contains(t, redirectURL, "SAMLRequest=")
				assert.True(t, len(requestID) > 0)
				assert.Equal(t, "_", requestID[:1])
			},
		},
		{
			name: "missing IdP SSO URL",
			sp:   sp,
			idp: IdPConfig{
				EntityID: "https://idp.example.com",
			},
			wantErr: true,
		},
		{
			name: "missing SP entity ID",
			sp:   SPConfig{ACSURL: "https://sp.example.com/saml/acs"},
			idp: IdPConfig{
				EntityID: "https://idp.example.com",
				SSOURL:   "https://idp.example.com/sso",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectURL, requestID, err := BuildAuthnRequest(tt.sp, tt.idp)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, redirectURL, requestID)
			}
		})
	}
}

func TestRequestTracker(t *testing.T) {
	t.Run("track and consume", func(t *testing.T) {
		tracker := NewRequestTracker(5 * time.Minute)
		tracker.Track("_req_123")
		assert.True(t, tracker.Consume("_req_123"))
		// Second consume should fail (already consumed).
		assert.False(t, tracker.Consume("_req_123"))
	})

	t.Run("unknown request", func(t *testing.T) {
		tracker := NewRequestTracker(5 * time.Minute)
		assert.False(t, tracker.Consume("_unknown"))
	})

	t.Run("expired request", func(t *testing.T) {
		tracker := NewRequestTracker(1 * time.Millisecond)
		tracker.Track("_req_expired")
		time.Sleep(5 * time.Millisecond)
		assert.False(t, tracker.Consume("_req_expired"))
	})

	t.Run("cleanup removes expired", func(t *testing.T) {
		tracker := NewRequestTracker(1 * time.Millisecond)
		tracker.Track("_req_1")
		tracker.Track("_req_2")
		time.Sleep(5 * time.Millisecond)
		tracker.Cleanup()
		tracker.mu.RLock()
		assert.Empty(t, tracker.pending)
		tracker.mu.RUnlock()
	})
}

func TestAssertionValidator_ValidateResponse(t *testing.T) {
	now := time.Now().UTC()
	spEntityID := "https://sp.example.com"
	acsURL := "https://sp.example.com/saml/acs"

	tests := []struct {
		name        string
		responseOpts []mockResponseOption
		setupTracker func(*RequestTracker)
		wantErr     bool
		errContains string
		check       func(t *testing.T, a *ParsedAssertion)
	}{
		{
			name: "valid response",
			responseOpts: []mockResponseOption{},
			check: func(t *testing.T, a *ParsedAssertion) {
				assert.Equal(t, "https://idp.example.com", a.Issuer)
				assert.Equal(t, "user@example.com", a.NameID)
				assert.Equal(t, NameIDFormatEmailAddress, a.NameIDFormat)
				assert.Equal(t, "_session_123", a.SessionIndex)
				assert.Equal(t, "Test User", a.Attributes[AttrDisplayName][0])
				assert.Equal(t, "user@example.com", a.Attributes[AttrEmailFriendly][0])
			},
		},
		{
			name: "with InResponseTo tracking",
			responseOpts: []mockResponseOption{
				withInResponseTo("_req_abc"),
			},
			setupTracker: func(rt *RequestTracker) {
				rt.Track("_req_abc")
			},
			check: func(t *testing.T, a *ParsedAssertion) {
				assert.Equal(t, "_req_abc", a.InResponseTo)
			},
		},
		{
			name: "InResponseTo mismatch",
			responseOpts: []mockResponseOption{
				withInResponseTo("_req_wrong"),
			},
			wantErr:     true,
			errContains: "request id mismatch",
		},
		{
			name: "non-success status",
			responseOpts: []mockResponseOption{
				withStatusCode("urn:oasis:names:tc:SAML:2.0:status:Requester"),
			},
			wantErr:     true,
			errContains: "non-success status",
		},
		{
			name: "no assertion",
			responseOpts: []mockResponseOption{
				withNoAssertion(),
			},
			wantErr:     true,
			errContains: "no assertions found",
		},
		{
			name: "expired assertion",
			responseOpts: []mockResponseOption{
				withNotOnOrAfter(now.Add(-10 * time.Minute)),
			},
			wantErr:     true,
			errContains: "assertion expired",
		},
		{
			name: "assertion not yet valid",
			responseOpts: []mockResponseOption{
				withNotBefore(now.Add(10 * time.Minute)),
			},
			wantErr:     true,
			errContains: "assertion not yet valid",
		},
		{
			name:        "invalid base64",
			wantErr:     true,
			errContains: "decode base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewRequestTracker(5 * time.Minute)
			if tt.setupTracker != nil {
				tt.setupTracker(tracker)
			}

			validator := NewAssertionValidator(spEntityID, acsURL, tracker,
				WithNowFunc(func() time.Time { return now }),
			)

			var responseB64 string
			if tt.name == "invalid base64" {
				responseB64 = "not-valid-base64!!!"
			} else {
				responseB64 = mockIdPResponse(t, tt.responseOpts...)
			}

			assertion, err := validator.ValidateResponse(responseB64)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, assertion)
			}
		})
	}
}

func TestAttributeMapping_MapAttributes(t *testing.T) {
	tests := []struct {
		name    string
		mapping AttributeMapping
		assertion *ParsedAssertion
		want    MappedUser
	}{
		{
			name:    "standard attributes",
			mapping: DefaultAttributeMapping(),
			assertion: &ParsedAssertion{
				NameID:       "user123",
				NameIDFormat: NameIDFormatPersistent,
				Attributes: map[string][]string{
					AttrEmailFriendly: {"user@example.com"},
					AttrDisplayName:   {"Jane Doe"},
					AttrGroupsFriendly: {"admins"},
				},
			},
			want: MappedUser{
				Email:  "user@example.com",
				Name:   "Jane Doe",
				Groups: []string{"admins"},
				Roles:  []string{domain.RoleUser}, // no group mapping configured
			},
		},
		{
			name: "with group-to-role mapping",
			mapping: AttributeMapping{
				EmailAttributes: []string{AttrEmailFriendly},
				NameAttributes:  []string{AttrDisplayName},
				GroupAttributes: []string{AttrGroupsFriendly},
				GroupRoleMap: map[string]string{
					"platform-admins": domain.RoleAdmin,
					"engineers":       domain.RoleUser,
				},
				DefaultRole: domain.RoleUser,
			},
			assertion: &ParsedAssertion{
				NameID:       "user456",
				NameIDFormat: NameIDFormatPersistent,
				Attributes: map[string][]string{
					AttrEmailFriendly:  {"admin@example.com"},
					AttrDisplayName:    {"Admin User"},
					AttrGroupsFriendly: {"platform-admins", "engineers"},
				},
			},
			want: MappedUser{
				Email:  "admin@example.com",
				Name:   "Admin User",
				Groups: []string{"platform-admins", "engineers"},
				// Both roles mapped (order may vary).
			},
		},
		{
			name:    "email from NameID when format is emailAddress",
			mapping: DefaultAttributeMapping(),
			assertion: &ParsedAssertion{
				NameID:       "user@example.com",
				NameIDFormat: NameIDFormatEmailAddress,
				Attributes:   map[string][]string{},
			},
			want: MappedUser{
				Email:  "user@example.com",
				Name:   "",
				Roles:  []string{domain.RoleUser},
			},
		},
		{
			name:    "name from given + surname",
			mapping: DefaultAttributeMapping(),
			assertion: &ParsedAssertion{
				NameID:       "user789",
				NameIDFormat: NameIDFormatPersistent,
				Attributes: map[string][]string{
					AttrEmailFriendly:     {"user@example.com"},
					AttrGivenName:         {"John"},
					AttrSurname:           {"Smith"},
				},
			},
			want: MappedUser{
				Email: "user@example.com",
				Name:  "John Smith",
				Roles: []string{domain.RoleUser},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mapping.MapAttributes(tt.assertion)
			assert.Equal(t, tt.want.Email, result.Email)
			assert.Equal(t, tt.want.Name, result.Name)
			if len(tt.want.Groups) > 0 {
				assert.ElementsMatch(t, tt.want.Groups, result.Groups)
			}

			// For group-to-role mapping, check both roles are present.
			if tt.name == "with group-to-role mapping" {
				assert.ElementsMatch(t, []string{domain.RoleAdmin, domain.RoleUser}, result.Roles)
			} else if len(tt.want.Roles) > 0 {
				assert.ElementsMatch(t, tt.want.Roles, result.Roles)
			}
		})
	}
}

func TestProvisioner_Provision(t *testing.T) {
	logger := zap.NewNop()

	baseAssertion := &ParsedAssertion{
		Issuer:       "https://idp.example.com",
		NameID:       "saml_user_123",
		NameIDFormat: NameIDFormatPersistent,
		SessionIndex: "_session_1",
		Attributes:   map[string][]string{},
	}

	baseMapped := MappedUser{
		Email: "user@example.com",
		Name:  "Test User",
		Roles: []string{domain.RoleUser},
	}

	t.Run("returning user with existing SAML identity", func(t *testing.T) {
		existingUser := &domain.User{
			ID:    "usr_existing",
			Email: "user@example.com",
			Name:  "Test User",
			Roles: []string{domain.RoleUser},
		}
		existingIdentity := &domain.SAMLIdentity{
			ID:          "sid_existing",
			UserID:      "usr_existing",
			IdPEntityID: "https://idp.example.com",
			NameID:      "saml_user_123",
		}

		userRepo := &mocks.MockUserRepository{
			FindByIDFn: func(_ context.Context, id string) (*domain.User, error) {
				if id == "usr_existing" {
					return existingUser, nil
				}
				return nil, storage.ErrNotFound
			},
			UpdateLastLoginFn: func(_ context.Context, _ string, _ time.Time) error { return nil },
		}
		identityRepo := &mocks.MockSAMLIdentityRepository{
			FindByIdPAndNameIDFn: func(_ context.Context, idpEntityID, nameID string) (*domain.SAMLIdentity, error) {
				if idpEntityID == "https://idp.example.com" && nameID == "saml_user_123" {
					return existingIdentity, nil
				}
				return nil, storage.ErrNotFound
			},
		}

		p := NewProvisioner(userRepo, identityRepo, logger)
		result, err := p.Provision(context.Background(), baseAssertion, baseMapped)

		require.NoError(t, err)
		assert.Equal(t, "usr_existing", result.User.ID)
		assert.Equal(t, "sid_existing", result.Identity.ID)
		assert.False(t, result.Created)
		assert.False(t, result.Linked)
	})

	t.Run("link to existing user by email", func(t *testing.T) {
		existingUser := &domain.User{
			ID:    "usr_by_email",
			Email: "user@example.com",
			Name:  "Existing User",
			Roles: []string{domain.RoleUser},
		}

		userRepo := &mocks.MockUserRepository{
			FindByEmailFn: func(_ context.Context, email string) (*domain.User, error) {
				if email == "user@example.com" {
					return existingUser, nil
				}
				return nil, storage.ErrNotFound
			},
			UpdateLastLoginFn: func(_ context.Context, _ string, _ time.Time) error { return nil },
		}
		identityRepo := &mocks.MockSAMLIdentityRepository{
			FindByIdPAndNameIDFn: func(_ context.Context, _, _ string) (*domain.SAMLIdentity, error) {
				return nil, storage.ErrNotFound
			},
			CreateFn: func(_ context.Context, identity *domain.SAMLIdentity) (*domain.SAMLIdentity, error) {
				return identity, nil
			},
		}

		p := NewProvisioner(userRepo, identityRepo, logger)
		result, err := p.Provision(context.Background(), baseAssertion, baseMapped)

		require.NoError(t, err)
		assert.Equal(t, "usr_by_email", result.User.ID)
		assert.False(t, result.Created)
		assert.True(t, result.Linked)
	})

	t.Run("JIT create new user", func(t *testing.T) {
		var createdUser *domain.User
		userRepo := &mocks.MockUserRepository{
			FindByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
				return nil, storage.ErrNotFound
			},
			CreateFn: func(_ context.Context, user *domain.User) (*domain.User, error) {
				createdUser = user
				return user, nil
			},
		}
		identityRepo := &mocks.MockSAMLIdentityRepository{
			FindByIdPAndNameIDFn: func(_ context.Context, _, _ string) (*domain.SAMLIdentity, error) {
				return nil, storage.ErrNotFound
			},
			CreateFn: func(_ context.Context, identity *domain.SAMLIdentity) (*domain.SAMLIdentity, error) {
				return identity, nil
			},
		}

		p := NewProvisioner(userRepo, identityRepo, logger)
		result, err := p.Provision(context.Background(), baseAssertion, baseMapped)

		require.NoError(t, err)
		assert.True(t, result.Created)
		assert.False(t, result.Linked)
		assert.Equal(t, "user@example.com", createdUser.Email)
		assert.Equal(t, "Test User", createdUser.Name)
		assert.True(t, createdUser.EmailVerified)
		assert.Equal(t, []string{domain.RoleUser}, createdUser.Roles)
	})

	t.Run("locked account rejected", func(t *testing.T) {
		lockedUser := &domain.User{
			ID:     "usr_locked",
			Email:  "locked@example.com",
			Locked: true,
		}

		userRepo := &mocks.MockUserRepository{
			FindByIDFn: func(_ context.Context, id string) (*domain.User, error) {
				return lockedUser, nil
			},
		}
		identityRepo := &mocks.MockSAMLIdentityRepository{
			FindByIdPAndNameIDFn: func(_ context.Context, _, _ string) (*domain.SAMLIdentity, error) {
				return &domain.SAMLIdentity{UserID: "usr_locked"}, nil
			},
		}

		p := NewProvisioner(userRepo, identityRepo, logger)
		_, err := p.Provision(context.Background(), baseAssertion, baseMapped)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrAccountLocked)
	})

	t.Run("JIT create fails without email", func(t *testing.T) {
		userRepo := &mocks.MockUserRepository{
			FindByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
				return nil, storage.ErrNotFound
			},
		}
		identityRepo := &mocks.MockSAMLIdentityRepository{
			FindByIdPAndNameIDFn: func(_ context.Context, _, _ string) (*domain.SAMLIdentity, error) {
				return nil, storage.ErrNotFound
			},
		}

		p := NewProvisioner(userRepo, identityRepo, logger)
		mappedNoEmail := MappedUser{Name: "No Email", Roles: []string{domain.RoleUser}}
		_, err := p.Provision(context.Background(), baseAssertion, mappedNoEmail)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrSAMLResponseInvalid)
	})
}

func TestService_InitiateLogin(t *testing.T) {
	logger := zap.NewNop()
	sp := SPConfig{
		EntityID: "https://sp.example.com",
		ACSURL:   "https://sp.example.com/saml/acs",
	}

	svc := NewService(sp,
		&mocks.MockUserRepository{},
		&mocks.MockSAMLIdentityRepository{},
		&mockRefreshTokenRepo{},
		&mockTokenIssuer{},
		audit.NopLogger{},
		logger,
	)

	t.Run("registered IdP", func(t *testing.T) {
		err := svc.RegisterIdP(IdPConfig{
			EntityID: "https://idp.example.com",
			SSOURL:   "https://idp.example.com/sso",
		}, DefaultAttributeMapping())
		require.NoError(t, err)

		url, err := svc.InitiateLogin("https://idp.example.com")
		require.NoError(t, err)
		assert.Contains(t, url, "https://idp.example.com/sso")
		assert.Contains(t, url, "SAMLRequest=")
	})

	t.Run("unregistered IdP", func(t *testing.T) {
		_, err := svc.InitiateLogin("https://unknown.idp.com")
		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrSAMLIdPNotConfigured)
	})
}

func TestService_HandleCallback(t *testing.T) {
	logger := zap.NewNop()
	sp := SPConfig{
		EntityID: "https://sp.example.com",
		ACSURL:   "https://sp.example.com/saml/acs",
	}

	t.Run("full flow - new user JIT provisioned", func(t *testing.T) {
		userRepo := &mocks.MockUserRepository{
			FindByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
				return nil, storage.ErrNotFound
			},
			CreateFn: func(_ context.Context, user *domain.User) (*domain.User, error) {
				return user, nil
			},
		}
		identityRepo := &mocks.MockSAMLIdentityRepository{
			FindByIdPAndNameIDFn: func(_ context.Context, _, _ string) (*domain.SAMLIdentity, error) {
				return nil, storage.ErrNotFound
			},
			CreateFn: func(_ context.Context, identity *domain.SAMLIdentity) (*domain.SAMLIdentity, error) {
				return identity, nil
			},
		}

		var issuedSubject string
		tokenIssuer := &mockTokenIssuer{
			IssueTokenPairFn: func(_ context.Context, subject string, roles, _ []string, clientType domain.ClientType) (*api.AuthResult, error) {
				issuedSubject = subject
				assert.Equal(t, domain.ClientTypeUser, clientType)
				return &api.AuthResult{
					AccessToken:  "qf_at_saml_test",
					RefreshToken: "qf_rt_saml_test",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				}, nil
			},
		}

		svc := NewService(sp, userRepo, identityRepo, &mockRefreshTokenRepo{}, tokenIssuer, audit.NopLogger{}, logger)
		err := svc.RegisterIdP(IdPConfig{
			EntityID: "https://idp.example.com",
			SSOURL:   "https://idp.example.com/sso",
		}, DefaultAttributeMapping())
		require.NoError(t, err)

		responseB64 := mockIdPResponse(t,
			withEmail("newuser@example.com"),
			withName("New User"),
			withGroups("engineering"),
		)

		result, err := svc.HandleCallback(context.Background(), responseB64)
		require.NoError(t, err)
		assert.Equal(t, "qf_at_saml_test", result.AccessToken)
		assert.Equal(t, "qf_rt_saml_test", result.RefreshToken)
		assert.NotEmpty(t, issuedSubject)
	})

	t.Run("returning user", func(t *testing.T) {
		existingUser := &domain.User{
			ID:    "usr_returning",
			Email: "returning@example.com",
			Name:  "Returning User",
			Roles: []string{domain.RoleUser},
		}

		userRepo := &mocks.MockUserRepository{
			FindByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
				return existingUser, nil
			},
			UpdateLastLoginFn: func(_ context.Context, _ string, _ time.Time) error { return nil },
		}
		identityRepo := &mocks.MockSAMLIdentityRepository{
			FindByIdPAndNameIDFn: func(_ context.Context, idp, nameID string) (*domain.SAMLIdentity, error) {
				return &domain.SAMLIdentity{
					ID:          "sid_existing",
					UserID:      "usr_returning",
					IdPEntityID: idp,
					NameID:      nameID,
				}, nil
			},
		}

		svc := NewService(sp, userRepo, identityRepo, &mockRefreshTokenRepo{}, &mockTokenIssuer{}, audit.NopLogger{}, logger)
		_ = svc.RegisterIdP(IdPConfig{
			EntityID: "https://idp.example.com",
			SSOURL:   "https://idp.example.com/sso",
		}, DefaultAttributeMapping())

		responseB64 := mockIdPResponse(t)
		result, err := svc.HandleCallback(context.Background(), responseB64)

		require.NoError(t, err)
		assert.Equal(t, "usr_returning", result.UserID)
	})

	t.Run("invalid response rejected", func(t *testing.T) {
		svc := NewService(sp,
			&mocks.MockUserRepository{},
			&mocks.MockSAMLIdentityRepository{},
			&mockRefreshTokenRepo{},
			&mockTokenIssuer{},
			audit.NopLogger{},
			logger,
		)

		_, err := svc.HandleCallback(context.Background(), "not-valid-base64!!!")
		require.Error(t, err)
	})
}

func TestService_RegisterIdP(t *testing.T) {
	logger := zap.NewNop()
	sp := SPConfig{
		EntityID: "https://sp.example.com",
		ACSURL:   "https://sp.example.com/saml/acs",
	}

	svc := NewService(sp,
		&mocks.MockUserRepository{},
		&mocks.MockSAMLIdentityRepository{},
		&mockRefreshTokenRepo{},
		&mockTokenIssuer{},
		audit.NopLogger{},
		logger,
	)

	t.Run("valid registration", func(t *testing.T) {
		err := svc.RegisterIdP(IdPConfig{
			EntityID: "https://idp1.example.com",
			SSOURL:   "https://idp1.example.com/sso",
		}, DefaultAttributeMapping())
		require.NoError(t, err)
		assert.Contains(t, svc.GetRegisteredIdPs(), "https://idp1.example.com")
	})

	t.Run("missing entity ID", func(t *testing.T) {
		err := svc.RegisterIdP(IdPConfig{
			SSOURL: "https://idp.example.com/sso",
		}, DefaultAttributeMapping())
		assert.Error(t, err)
	})

	t.Run("missing SSO URL", func(t *testing.T) {
		err := svc.RegisterIdP(IdPConfig{
			EntityID: "https://idp.example.com",
		}, DefaultAttributeMapping())
		assert.Error(t, err)
	})
}

func TestService_GetMetadata(t *testing.T) {
	logger := zap.NewNop()
	sp := SPConfig{
		EntityID:             "https://sp.example.com",
		ACSURL:               "https://sp.example.com/saml/acs",
		WantAssertionsSigned: true,
	}

	svc := NewService(sp,
		&mocks.MockUserRepository{},
		&mocks.MockSAMLIdentityRepository{},
		&mockRefreshTokenRepo{},
		&mockTokenIssuer{},
		audit.NopLogger{},
		logger,
	)

	data, err := svc.GetMetadata()
	require.NoError(t, err)
	assert.Contains(t, string(data), "https://sp.example.com")
	assert.Contains(t, string(data), "https://sp.example.com/saml/acs")
}

func TestDeflateAndEncode_RoundTrip(t *testing.T) {
	original := []byte("<samlp:AuthnRequest>test data</samlp:AuthnRequest>")
	encoded, err := deflateAndEncode(original)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	decoded, err := decodeAndInflate(encoded)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestDefaultAttributeMapping(t *testing.T) {
	m := DefaultAttributeMapping()
	assert.NotEmpty(t, m.EmailAttributes)
	assert.NotEmpty(t, m.NameAttributes)
	assert.NotEmpty(t, m.GroupAttributes)
	assert.Equal(t, domain.RoleUser, m.DefaultRole)
	assert.Empty(t, m.GroupRoleMap)
}

func TestGenerateRequestID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := generateRequestID()
		require.NoError(t, err)
		assert.True(t, len(id) > 1, "ID should not be empty")
		assert.Equal(t, "_", id[:1], "ID must start with underscore")
		assert.False(t, ids[id], "duplicate ID generated: %s", id)
		ids[id] = true
	}
}

func TestAssertionValidator_RegisterIdPCertificate(t *testing.T) {
	validator := NewAssertionValidator("sp", "acs", nil)

	t.Run("invalid PEM", func(t *testing.T) {
		err := validator.RegisterIdPCertificate("idp1", "not-a-pem")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no PEM block found")
	})

	t.Run("invalid certificate data", func(t *testing.T) {
		invalidPEM := "-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----"
		err := validator.RegisterIdPCertificate("idp2", invalidPEM)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parse certificate")
	})
}

func TestProvisioner_DuplicateEmailRace(t *testing.T) {
	logger := zap.NewNop()

	assertion := &ParsedAssertion{
		Issuer:       "https://idp.example.com",
		NameID:       "race_user",
		NameIDFormat: NameIDFormatPersistent,
		Attributes:   map[string][]string{},
	}
	mapped := MappedUser{
		Email: "race@example.com",
		Name:  "Race Condition User",
		Roles: []string{domain.RoleUser},
	}

	userRepo := &mocks.MockUserRepository{
		FindByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
		CreateFn: func(_ context.Context, _ *domain.User) (*domain.User, error) {
			return nil, storage.ErrDuplicateEmail
		},
	}
	identityRepo := &mocks.MockSAMLIdentityRepository{
		FindByIdPAndNameIDFn: func(_ context.Context, _, _ string) (*domain.SAMLIdentity, error) {
			return nil, storage.ErrNotFound
		},
	}

	p := NewProvisioner(userRepo, identityRepo, logger)
	_, err := p.Provision(context.Background(), assertion, mapped)

	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrUserAlreadyExists)
}

// Suppress unused import warnings: these are used via the test mocks.
var _ = fmt.Sprintf
