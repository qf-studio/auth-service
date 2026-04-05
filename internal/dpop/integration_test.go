package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/dpop"
	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/token"
)

// TestIntegration_DPoP_FullFlow tests the complete DPoP flow:
// 1. Issue a DPoP-bound token pair via the token service
// 2. Present the token with a DPoP proof to a protected endpoint
// 3. Verify the proof is validated and request succeeds
// 4. Verify that a request without proof is rejected
// 5. Verify that a proof with wrong key is rejected
func TestIntegration_DPoP_FullFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup Redis.
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	log := zap.NewNop()
	auditor := audit.NewService(log, 64)
	defer auditor.Close()

	// Setup token service.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret"},
	}
	tokenSvc, err := token.NewServiceFromKey(jwtCfg, key, redisClient, log, auditor)
	require.NoError(t, err)

	// Setup DPoP service.
	dpopCfg := config.DPoPConfig{
		Enabled:   true,
		NonceTTL:  5 * time.Minute,
		JTIWindow: 1 * time.Minute,
	}
	dpopSvc := dpop.NewService(dpopCfg, redisClient, log)
	dpopAdapter := dpop.NewMiddlewareAdapter(dpopSvc)

	// Generate client DPoP key pair.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ctx := context.Background()

	// Step 1: Compute thumbprint and issue DPoP-bound token pair.
	thumbprint := computeThumbprint(t, &clientKey.PublicKey)
	result, err := tokenSvc.IssueTokenPairDPoP(ctx, "user-integration", []string{"user"}, nil, domain.ClientTypeUser, thumbprint)
	require.NoError(t, err)
	assert.Equal(t, "DPoP", result.TokenType)
	assert.True(t, strings.HasPrefix(result.AccessToken, "qf_at_"))

	// Verify the token contains cnf.jkt claim.
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := tokenSvc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	assert.Equal(t, thumbprint, claims.JWKThumbprint)
	assert.Equal(t, "user-integration", claims.Subject)

	// Step 2: Build a test router with auth + DPoP middleware.
	requestURIFn := func(c *gin.Context) string {
		return "https://auth.example.com" + c.Request.URL.Path
	}

	router := gin.New()
	router.Use(middleware.AuthMiddleware(tokenSvc))
	router.Use(middleware.DPoPMiddleware(dpopAdapter, requestURIFn))
	router.GET("/auth/me", func(c *gin.Context) {
		mwClaims, err := middleware.GetClaims(c)
		if err != nil {
			c.String(http.StatusInternalServerError, "no claims")
			return
		}
		dpopThumb := middleware.GetDPoPThumbprint(c)
		c.JSON(http.StatusOK, gin.H{
			"user_id":         mwClaims.Subject,
			"dpop_thumbprint": dpopThumb,
		})
	})

	// Step 3: Request with valid DPoP proof succeeds.
	proof := createDPoPProof(t, clientKey, "GET", "https://auth.example.com/auth/me", "integ-jti-1", time.Now(), nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)
	req.Header.Set("DPoP", proof)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "user-integration")
	assert.Contains(t, w.Body.String(), thumbprint)

	// Step 4: Request without DPoP proof is rejected (token is bound).
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "DPoP proof required")

	// Step 5: Request with wrong key's proof is rejected.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wrongProof := createDPoPProof(t, wrongKey, "GET", "https://auth.example.com/auth/me", "integ-jti-2", time.Now(), nil)
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)
	req.Header.Set("DPoP", wrongProof)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "does not match")
}

// TestIntegration_DPoP_UnboundToken_NoDPoPRequired tests that tokens without
// cnf.jkt (plain Bearer) pass through the DPoP middleware without issue.
func TestIntegration_DPoP_UnboundToken_NoDPoPRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	log := zap.NewNop()
	auditor := audit.NewService(log, 64)
	defer auditor.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret"},
	}
	tokenSvc, err := token.NewServiceFromKey(jwtCfg, key, redisClient, log, auditor)
	require.NoError(t, err)

	dpopCfg := config.DPoPConfig{Enabled: true, NonceTTL: 5 * time.Minute, JTIWindow: time.Minute}
	dpopSvc := dpop.NewService(dpopCfg, redisClient, log)
	dpopAdapter := dpop.NewMiddlewareAdapter(dpopSvc)

	ctx := context.Background()

	// Issue a plain Bearer token (no DPoP thumbprint).
	result, err := tokenSvc.IssueTokenPair(ctx, "user-bearer", []string{"user"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	assert.Equal(t, "Bearer", result.TokenType)

	requestURIFn := func(c *gin.Context) string {
		return "https://auth.example.com" + c.Request.URL.Path
	}

	router := gin.New()
	router.Use(middleware.AuthMiddleware(tokenSvc))
	router.Use(middleware.DPoPMiddleware(dpopAdapter, requestURIFn))
	router.GET("/auth/me", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Plain Bearer request should pass through DPoP middleware.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestIntegration_DPoP_TokenEndpoint_BindsToken tests DPoP binding during
// token issuance at the /auth/token endpoint.
func TestIntegration_DPoP_TokenEndpoint_BindsToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	log := zap.NewNop()
	auditor := audit.NewService(log, 64)
	defer auditor.Close()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret"},
	}
	tokenSvc, err := token.NewServiceFromKey(jwtCfg, serverKey, redisClient, log, auditor)
	require.NoError(t, err)

	dpopCfg := config.DPoPConfig{Enabled: true, NonceTTL: 5 * time.Minute, JTIWindow: time.Minute}
	dpopSvc := dpop.NewService(dpopCfg, redisClient, log)
	handlerAdapter := dpop.NewHandlerAdapter(dpopSvc)

	// Client key for DPoP.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ctx := context.Background()

	// First, get a refresh token (plain Bearer).
	initialResult, err := tokenSvc.IssueTokenPair(ctx, "user-dpop-bind", []string{"user"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Now simulate what the token handler does:
	// 1. Extract DPoP proof from header
	// 2. Validate it
	// 3. Pass thumbprint to RefreshDPoP

	proof := createDPoPProof(t, clientKey, "POST", "https://auth.example.com/auth/token", "token-jti-1", time.Now(), nil)

	// Validate the proof.
	thumbprint, err := handlerAdapter.ValidateProof(ctx, proof, "POST", "https://auth.example.com/auth/token")
	require.NoError(t, err)
	assert.NotEmpty(t, thumbprint)

	// Issue DPoP-bound tokens.
	boundResult, err := tokenSvc.RefreshDPoP(ctx, initialResult.RefreshToken, thumbprint)
	require.NoError(t, err)
	assert.Equal(t, "DPoP", boundResult.TokenType)

	// Verify the new access token has the cnf.jkt claim.
	rawJWT := strings.TrimPrefix(boundResult.AccessToken, "qf_at_")
	boundClaims, err := tokenSvc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	assert.Equal(t, thumbprint, boundClaims.JWKThumbprint)
	assert.Equal(t, "user-dpop-bind", boundClaims.Subject)
}

// TestIntegration_DPoP_RefreshDPoP tests the RefreshDPoP method directly.
func TestIntegration_DPoP_RefreshDPoP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	log := zap.NewNop()
	auditor := audit.NewService(log, 64)
	defer auditor.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret"},
	}
	tokenSvc, err := token.NewServiceFromKey(jwtCfg, key, redisClient, log, auditor)
	require.NoError(t, err)

	ctx := context.Background()

	// Issue initial token pair.
	initial, err := tokenSvc.IssueTokenPair(ctx, "user-refresh", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Refresh with DPoP binding.
	result, err := tokenSvc.RefreshDPoP(ctx, initial.RefreshToken, "test-thumbprint")
	require.NoError(t, err)
	assert.Equal(t, "DPoP", result.TokenType)

	// Verify cnf.jkt in the new token.
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := tokenSvc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	assert.Equal(t, "test-thumbprint", claims.JWKThumbprint)

	// Old refresh token should be revoked (rotated).
	_, err = tokenSvc.Refresh(ctx, initial.RefreshToken)
	assert.Error(t, err)
}

// TestIntegration_DPoP_IssueTokenPairDPoP_TokenType tests that IssueTokenPairDPoP
// returns "DPoP" token type when thumbprint is provided and "Bearer" when not.
func TestIntegration_DPoP_IssueTokenPairDPoP_TokenType(t *testing.T) {
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	log := zap.NewNop()
	auditor := audit.NewService(log, 64)
	defer auditor.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"secret"},
	}
	tokenSvc, err := token.NewServiceFromKey(jwtCfg, key, redisClient, log, auditor)
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name          string
		thumbprint    string
		wantTokenType string
		wantHasCNF    bool
	}{
		{
			name:          "with thumbprint returns DPoP",
			thumbprint:    "some-thumbprint-hash",
			wantTokenType: "DPoP",
			wantHasCNF:    true,
		},
		{
			name:          "without thumbprint returns Bearer",
			thumbprint:    "",
			wantTokenType: "Bearer",
			wantHasCNF:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tokenSvc.IssueTokenPairDPoP(ctx, "user-"+tc.name, nil, nil, domain.ClientTypeUser, tc.thumbprint)
			require.NoError(t, err)
			assert.Equal(t, tc.wantTokenType, result.TokenType)

			// Parse and verify cnf claim.
			rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
			claims, err := tokenSvc.ValidateToken(ctx, rawJWT)
			require.NoError(t, err)

			if tc.wantHasCNF {
				assert.Equal(t, tc.thumbprint, claims.JWKThumbprint)
			} else {
				assert.Empty(t, claims.JWKThumbprint)
			}
		})
	}
}

// Helper: create signed DPoP proof (already defined in service_test.go, but we re-use it via the
// package test scope since both files are in dpop_test package).

// verifyTokenClaims is a helper for the token handler adapter tests.
// It does NOT use _ for unused results.
func verifyTokenClaims(t *testing.T, tokenSvc *token.Service, accessToken string) *domain.TokenClaims {
	t.Helper()
	rawJWT := strings.TrimPrefix(accessToken, "qf_at_")
	claims, err := tokenSvc.ValidateToken(context.Background(), rawJWT)
	require.NoError(t, err)
	return claims
}

// verifyBound is a compact helper to check for unused return values.
func verifyBound(t *testing.T, result *api.AuthResult, tokenSvc *token.Service, thumbprint string) {
	t.Helper()
	assert.Equal(t, "DPoP", result.TokenType)
	claims := verifyTokenClaims(t, tokenSvc, result.AccessToken)
	assert.Equal(t, thumbprint, claims.JWKThumbprint)
}

// verifyUnbound is a compact helper to check for unused return values.
func verifyUnbound(t *testing.T, result *api.AuthResult, tokenSvc *token.Service) {
	t.Helper()
	assert.Equal(t, "Bearer", result.TokenType)
	claims := verifyTokenClaims(t, tokenSvc, result.AccessToken)
	assert.Empty(t, claims.JWKThumbprint)
}

// TestIntegration_DPoP_CnfClaim_InJWT verifies the cnf claim appears as
// {"cnf":{"jkt":"..."}} in the raw JWT payload.
func TestIntegration_DPoP_CnfClaim_InJWT(t *testing.T) {
	mr := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	log := zap.NewNop()
	auditor := audit.NewService(log, 64)
	defer auditor.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"secret"},
	}
	tokenSvc, err := token.NewServiceFromKey(jwtCfg, key, redisClient, log, auditor)
	require.NoError(t, err)

	ctx := context.Background()

	result, err := tokenSvc.IssueTokenPairDPoP(ctx, "user-cnf", nil, nil, domain.ClientTypeUser, "my-thumbprint")
	require.NoError(t, err)

	// Parse the raw JWT to verify cnf claim structure.
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	parser := jwt.NewParser()
	parsedToken, _, err := parser.ParseUnverified(rawJWT, jwt.MapClaims{})
	require.NoError(t, err)

	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	cnfRaw, exists := mapClaims["cnf"]
	require.True(t, exists, "cnf claim must exist in DPoP-bound token")

	cnfMap, ok := cnfRaw.(map[string]interface{})
	require.True(t, ok, "cnf must be a JSON object")

	jkt, ok := cnfMap["jkt"].(string)
	require.True(t, ok, "cnf.jkt must be a string")
	assert.Equal(t, "my-thumbprint", jkt)
}
