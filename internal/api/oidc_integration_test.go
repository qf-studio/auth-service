package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
)

// ── Integration Test: Complete Authorization Code Flow ─────────────────────────
//
// This test exercises the full OIDC authorization code flow through the HTTP layer:
//   1. Client registers (admin API)
//   2. GET /oauth/authorize → redirect to login UI
//   3. PUT /admin/oauth/auth/requests/login (accept) → redirect to consent
//   4. PUT /admin/oauth/auth/requests/consent (accept) → redirect with code
//   5. POST /oauth/token (authorization_code exchange) → access + ID token
//   6. GET /userinfo → user claims

func TestOIDCAuthorizationCodeFlow_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// ── State shared across flow steps ──────────────────────────────────
	var (
		loginChallenge   = "login-challenge-integ"
		consentChallenge = "consent-challenge-integ"
		authorizationCode = "auth_code_integ_xyz"
		clientID         = "integ-client-1"
		userID           = "user-integ-123"
	)

	// ── Mock OIDC provider (coordinates the flow) ────────────────────────
	oidcSvc := &mockOIDCProviderService{
		getDiscoveryFn: func(_ context.Context) (*api.OIDCDiscoveryResponse, error) {
			return &api.OIDCDiscoveryResponse{
				Issuer:                           "https://auth.qf.studio",
				AuthorizationEndpoint:            "https://auth.qf.studio/oauth/authorize",
				TokenEndpoint:                    "https://auth.qf.studio/oauth/token",
				UserinfoEndpoint:                 "https://auth.qf.studio/userinfo",
				JwksURI:                          "https://auth.qf.studio/.well-known/jwks.json",
				ScopesSupported:                  []string{"openid", "profile", "email", "offline_access"},
				ResponseTypesSupported:           []string{"code"},
				GrantTypesSupported:              []string{"authorization_code", "refresh_token"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"ES256"},
				TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
				CodeChallengeMethodsSupported:     []string{"S256"},
			}, nil
		},
		authorizeFn: func(_ context.Context, req *api.AuthorizeRequest) (*api.AuthorizeResponse, error) {
			if req.ClientID == "" || req.RedirectURI == "" {
				return nil, api.ErrNotFound
			}
			// Authorization endpoint redirects to login UI with challenge.
			return &api.AuthorizeResponse{
				RedirectTo: "https://login.qf.studio/login?login_challenge=" + loginChallenge,
			}, nil
		},
		exchangeCodeFn: func(_ context.Context, req *api.CodeExchangeRequest) (*api.OIDCTokenResponse, error) {
			if req.Code != authorizationCode {
				return nil, api.ErrUnauthorized
			}
			if req.ClientID != clientID {
				return nil, api.ErrUnauthorized
			}
			return &api.OIDCTokenResponse{
				AccessToken:  "qf_at_integ_access_token",
				TokenType:    "Bearer",
				ExpiresIn:    900,
				RefreshToken: "qf_rt_integ_refresh_token",
				IDToken:      "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGgucWYuc3R1ZGlvIiwic3ViIjoidXNlci1pbnRlZy0xMjMiLCJhdWQiOlsiaW50ZWctY2xpZW50LTEiXSwiZXhwIjoxOTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDAsIm5vbmNlIjoiaW50ZWctbm9uY2UifQ.test_signature",
				Scope:        "openid profile email",
			}, nil
		},
		getUserInfoFn: func(_ context.Context, uid string) (*api.OIDCUserInfoResponse, error) {
			if uid != userID {
				return nil, api.ErrNotFound
			}
			return &api.OIDCUserInfoResponse{
				Sub:           uid,
				Email:         "integ@example.com",
				EmailVerified: true,
				Name:          "Integration User",
			}, nil
		},
	}

	// ── Mock consent service (admin login/consent flow) ──────────────────
	consentSvc := &mockConsentService{
		getLoginRequestFn: func(_ context.Context, challenge string) (*api.LoginRequestInfo, error) {
			if challenge != loginChallenge {
				return nil, api.ErrNotFound
			}
			return &api.LoginRequestInfo{
				Challenge:  challenge,
				ClientID:   clientID,
				Scope:      "openid profile email",
				RequestURL: "https://auth.qf.studio/oauth/authorize?client_id=" + clientID,
			}, nil
		},
		acceptLoginFn: func(_ context.Context, challenge string, req *api.AcceptLoginRequest) (*api.RedirectResponse, error) {
			if challenge != loginChallenge {
				return nil, api.ErrNotFound
			}
			if req.Subject == "" {
				return nil, api.ErrUnauthorized
			}
			// After login accept, redirect to consent.
			return &api.RedirectResponse{
				RedirectTo: "https://auth.qf.studio/consent?consent_challenge=" + consentChallenge,
			}, nil
		},
		getConsentRequestFn: func(_ context.Context, challenge string) (*api.ConsentRequestInfo, error) {
			if challenge != consentChallenge {
				return nil, api.ErrNotFound
			}
			return &api.ConsentRequestInfo{
				Challenge:       challenge,
				ClientID:        clientID,
				RequestedScopes: []string{"openid", "profile", "email"},
				Subject:         userID,
			}, nil
		},
		acceptConsentFn: func(_ context.Context, challenge string, req *api.AcceptConsentRequest) (*api.RedirectResponse, error) {
			if challenge != consentChallenge {
				return nil, api.ErrNotFound
			}
			// After consent accept, redirect with authorization code.
			return &api.RedirectResponse{
				RedirectTo: "https://app.example.com/cb?code=" + authorizationCode + "&state=csrf-integ",
			}, nil
		},
	}

	// ── Mock client approval service ─────────────────────────────────────
	approvalSvc := &mockClientApprovalService{
		createThirdPartyClientFn: func(_ context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
			return &api.AdminClientWithSecret{
				AdminClient: api.AdminClient{
					ID:         clientID,
					Name:       req.Name,
					ClientType: req.ClientType,
					Scopes:     req.Scopes,
					CreatedAt:  time.Now(),
					UpdatedAt:  time.Now(),
				},
				ClientSecret: "qf_cs_integ_secret",
			}, nil
		},
	}

	// ── Build routers ────────────────────────────────────────────────────
	authMW := func(c *gin.Context) {
		uid := c.GetHeader("X-User-ID")
		if uid == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing authentication")
			return
		}
		c.Set("user_id", uid)
		c.Next()
	}

	publicRouter := api.NewPublicRouter(
		&api.Services{
			Auth:  &mockAuthService{},
			Token: &mockTokenService{},
			OIDC:  oidcSvc,
		},
		&api.MiddlewareStack{Auth: authMW},
		health.NewService(),
	)

	adminRouter := api.NewAdminRouter(
		&api.AdminServices{
			Consent:        consentSvc,
			ClientApproval: approvalSvc,
		},
		&api.AdminDeps{Health: health.NewService()},
	)

	// ════════════════════════════════════════════════════════════════════════
	// STEP 1: Verify client approval endpoint exists (admin API)
	// ════════════════════════════════════════════════════════════════════════
	t.Run("Step1_ClientApprovalEndpoint", func(t *testing.T) {
		// Approve a client (verifying the admin approval workflow route).
		w := doRequest(adminRouter, http.MethodGet, "/admin/clients/"+clientID+"/approve", nil)
		require.Equal(t, http.StatusOK, w.Code)

		var resp api.ClientApprovalInfo
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, clientID, resp.ClientID)
		assert.True(t, resp.Approved)
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 2: Initiate authorization (GET /oauth/authorize)
	// ════════════════════════════════════════════════════════════════════════
	var authorizeRedirectURL string
	t.Run("Step2_Authorize", func(t *testing.T) {
		w := doRequest(publicRouter, http.MethodGet,
			"/oauth/authorize?client_id="+clientID+
				"&redirect_uri=https://app.example.com/cb"+
				"&response_type=code"+
				"&scope=openid+profile+email"+
				"&state=csrf-integ"+
				"&nonce=integ-nonce"+
				"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"+
				"&code_challenge_method=S256",
			nil)
		require.Equal(t, http.StatusFound, w.Code)

		authorizeRedirectURL = w.Header().Get("Location")
		assert.Contains(t, authorizeRedirectURL, "login_challenge="+loginChallenge)
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 3: Login accept (admin API)
	// ════════════════════════════════════════════════════════════════════════
	t.Run("Step3_AcceptLogin", func(t *testing.T) {
		// First, get login request details.
		w := doRequest(adminRouter, http.MethodGet,
			"/admin/oauth/auth/requests/login?login_challenge="+loginChallenge, nil)
		require.Equal(t, http.StatusOK, w.Code)

		var loginInfo api.LoginRequestInfo
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &loginInfo))
		assert.Equal(t, loginChallenge, loginInfo.Challenge)
		assert.Equal(t, clientID, loginInfo.ClientID)
		assert.Contains(t, loginInfo.Scope, "openid")

		// Accept the login.
		body := map[string]interface{}{
			"subject":  userID,
			"remember": true,
		}
		w = doRequest(adminRouter, http.MethodPut,
			"/admin/oauth/auth/requests/login?login_challenge="+loginChallenge+"&accept=true", body)
		require.Equal(t, http.StatusOK, w.Code)

		var redirect api.RedirectResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &redirect))
		assert.Contains(t, redirect.RedirectTo, "consent_challenge="+consentChallenge)
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 4: Consent accept (admin API)
	// ════════════════════════════════════════════════════════════════════════
	var codeRedirectURL string
	t.Run("Step4_AcceptConsent", func(t *testing.T) {
		// Get consent request details.
		w := doRequest(adminRouter, http.MethodGet,
			"/admin/oauth/auth/requests/consent?consent_challenge="+consentChallenge, nil)
		require.Equal(t, http.StatusOK, w.Code)

		var consentInfo api.ConsentRequestInfo
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &consentInfo))
		assert.Equal(t, consentChallenge, consentInfo.Challenge)
		assert.Equal(t, userID, consentInfo.Subject)
		assert.Contains(t, consentInfo.RequestedScopes, "openid")

		// Accept consent.
		body := map[string]interface{}{
			"granted_scopes": []string{"openid", "profile", "email"},
			"remember":       true,
		}
		w = doRequest(adminRouter, http.MethodPut,
			"/admin/oauth/auth/requests/consent?consent_challenge="+consentChallenge+"&accept=true", body)
		require.Equal(t, http.StatusOK, w.Code)

		var redirect api.RedirectResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &redirect))
		codeRedirectURL = redirect.RedirectTo
		assert.Contains(t, codeRedirectURL, "code="+authorizationCode)
		assert.Contains(t, codeRedirectURL, "state=csrf-integ")
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 5: Exchange code for tokens (POST /oauth/token)
	// ════════════════════════════════════════════════════════════════════════
	var tokenResp api.OIDCTokenResponse
	t.Run("Step5_ExchangeCode", func(t *testing.T) {
		// Extract code from redirect URL.
		parsedURL, err := url.Parse(codeRedirectURL)
		require.NoError(t, err)
		code := parsedURL.Query().Get("code")
		assert.Equal(t, authorizationCode, code)

		body := map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  "https://app.example.com/cb",
			"client_id":     clientID,
			"code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		}
		w := doRequest(publicRouter, http.MethodPost, "/oauth/token", body)
		require.Equal(t, http.StatusOK, w.Code)

		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokenResp))

		// Verify token response per OIDC Core §3.1.3.3.
		assert.NotEmpty(t, tokenResp.AccessToken, "access_token is REQUIRED")
		assert.Equal(t, "Bearer", tokenResp.TokenType, "token_type is REQUIRED")
		assert.Greater(t, tokenResp.ExpiresIn, 0, "expires_in is RECOMMENDED")
		assert.NotEmpty(t, tokenResp.IDToken, "id_token is REQUIRED when openid scope is granted")
		assert.NotEmpty(t, tokenResp.Scope, "scope should be returned")

		// Cache control headers per RFC 6749 §5.1.
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 5b: Invalid code exchange should fail
	// ════════════════════════════════════════════════════════════════════════
	t.Run("Step5b_InvalidCodeFails", func(t *testing.T) {
		body := map[string]string{
			"grant_type":   "authorization_code",
			"code":         "bad_code",
			"redirect_uri": "https://app.example.com/cb",
			"client_id":    clientID,
		}
		w := doRequest(publicRouter, http.MethodPost, "/oauth/token", body)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 6: Call UserInfo endpoint
	// ════════════════════════════════════════════════════════════════════════
	t.Run("Step6_UserInfo", func(t *testing.T) {
		w := doRequest(publicRouter, http.MethodGet, "/userinfo", nil, "X-User-ID", userID)
		require.Equal(t, http.StatusOK, w.Code)

		var userInfo api.OIDCUserInfoResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &userInfo))

		// Verify UserInfo claims per OIDC Core §5.3.
		assert.Equal(t, userID, userInfo.Sub, "sub is REQUIRED and must match the access token subject")
		assert.Equal(t, "integ@example.com", userInfo.Email)
		assert.True(t, userInfo.EmailVerified)
		assert.Equal(t, "Integration User", userInfo.Name)
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 6b: UserInfo without authentication should fail
	// ════════════════════════════════════════════════════════════════════════
	t.Run("Step6b_UserInfoUnauth", func(t *testing.T) {
		w := doRequest(publicRouter, http.MethodGet, "/userinfo", nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	// ════════════════════════════════════════════════════════════════════════
	// STEP 7: Verify discovery document consistency
	// ════════════════════════════════════════════════════════════════════════
	t.Run("Step7_DiscoveryConsistency", func(t *testing.T) {
		w := doRequest(publicRouter, http.MethodGet, "/.well-known/openid-configuration", nil)
		require.Equal(t, http.StatusOK, w.Code)

		var disc api.OIDCDiscoveryResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &disc))

		// Issuer must match throughout the flow.
		assert.Equal(t, "https://auth.qf.studio", disc.Issuer)
		assert.Contains(t, disc.ScopesSupported, "openid")
		assert.Contains(t, disc.ScopesSupported, "profile")
		assert.Contains(t, disc.ScopesSupported, "email")
		assert.Contains(t, disc.ResponseTypesSupported, "code")
		assert.Contains(t, disc.GrantTypesSupported, "authorization_code")
		assert.Contains(t, disc.CodeChallengeMethodsSupported, "S256")
	})
}

// ── Integration Test: Login Rejection Flow ────────────────────────────────────

func TestOIDCFlow_LoginRejection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	consentSvc := &mockConsentService{
		rejectLoginFn: func(_ context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error) {
			return &api.RedirectResponse{
				RedirectTo: "https://app.example.com/cb?error=" + req.Error + "&error_description=" + url.QueryEscape(req.ErrorDescription),
			}, nil
		},
	}

	adminRouter := api.NewAdminRouter(
		&api.AdminServices{Consent: consentSvc},
		&api.AdminDeps{Health: health.NewService()},
	)

	body := map[string]interface{}{
		"error":             "access_denied",
		"error_description": "user declined login",
	}
	w := doRequest(adminRouter, http.MethodPut,
		"/admin/oauth/auth/requests/login?login_challenge=rej-challenge&accept=false", body)
	require.Equal(t, http.StatusOK, w.Code)

	var redirect api.RedirectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &redirect))
	assert.Contains(t, redirect.RedirectTo, "error=access_denied")
}

// ── Integration Test: Consent Rejection Flow ──────────────────────────────────

func TestOIDCFlow_ConsentRejection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	consentSvc := &mockConsentService{
		rejectConsentFn: func(_ context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error) {
			return &api.RedirectResponse{
				RedirectTo: "https://app.example.com/cb?error=" + req.Error,
			}, nil
		},
	}

	adminRouter := api.NewAdminRouter(
		&api.AdminServices{Consent: consentSvc},
		&api.AdminDeps{Health: health.NewService()},
	)

	body := map[string]interface{}{
		"error":             "consent_required",
		"error_description": "user denied consent",
	}
	w := doRequest(adminRouter, http.MethodPut,
		"/admin/oauth/auth/requests/consent?consent_challenge=rej-consent&accept=false", body)
	require.Equal(t, http.StatusOK, w.Code)

	var redirect api.RedirectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &redirect))
	assert.Contains(t, redirect.RedirectTo, "error=consent_required")
}
