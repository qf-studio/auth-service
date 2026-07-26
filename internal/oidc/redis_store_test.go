package oidc_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/oidc"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, redis.Cmdable) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

// ────────────────────────────────────────────────────────────────────────────
// Login request tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisStore_SaveAndGetLoginRequest(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	lr := &oidc.LoginRequest{
		Challenge:           "login-chal-1",
		ClientID:            "client-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid", "profile"},
		State:               "state-1",
		Nonce:               "nonce-1",
		CodeChallenge:       "challenge-1",
		CodeChallengeMethod: "S256",
		RequestedAt:         time.Now().UTC().Truncate(time.Second),
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second),
	}

	require.NoError(t, store.SaveLoginRequest(ctx, lr))

	got, err := store.GetLoginRequest(ctx, "login-chal-1")
	require.NoError(t, err)
	assert.Equal(t, lr, got)

	// Non-destructive: a second Get should still succeed.
	got2, err := store.GetLoginRequest(ctx, "login-chal-1")
	require.NoError(t, err)
	assert.Equal(t, lr, got2)
}

func TestRedisStore_GetLoginRequest_NotFound(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	_, err := store.GetLoginRequest(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrLoginRequestNotFound)
}

func TestRedisStore_ConsumeLoginRequest(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	lr := &oidc.LoginRequest{Challenge: "login-chal-consume", ClientID: "client-1"}
	require.NoError(t, store.SaveLoginRequest(ctx, lr))

	got, err := store.ConsumeLoginRequest(ctx, "login-chal-consume")
	require.NoError(t, err)
	assert.Equal(t, "client-1", got.ClientID)

	// GETDEL semantics: second consume must fail (single-use).
	_, err = store.ConsumeLoginRequest(ctx, "login-chal-consume")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrLoginRequestNotFound)
}

func TestRedisStore_LoginRequest_TTLExpires(t *testing.T) {
	mr, client := newTestRedis(t)
	store := oidc.NewRedisStore(client, oidc.WithChallengeTTL(1*time.Second))
	ctx := context.Background()

	lr := &oidc.LoginRequest{Challenge: "login-chal-expire", ClientID: "client-1"}
	require.NoError(t, store.SaveLoginRequest(ctx, lr))

	mr.FastForward(2 * time.Second)

	_, err := store.GetLoginRequest(ctx, "login-chal-expire")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrLoginRequestNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// Consent request tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisStore_SaveAndGetConsentRequest(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	cr := &oidc.ConsentRequest{
		Challenge:           "consent-chal-1",
		Subject:             "user-1",
		ClientID:            "client-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid", "email"},
		Nonce:               "nonce-1",
		CodeChallenge:       "challenge-1",
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().UTC().Truncate(time.Second),
		ExpiresAt:           time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second),
	}

	require.NoError(t, store.SaveConsentRequest(ctx, cr))

	got, err := store.GetConsentRequest(ctx, "consent-chal-1")
	require.NoError(t, err)
	assert.Equal(t, cr, got)
}

func TestRedisStore_GetConsentRequest_NotFound(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	_, err := store.GetConsentRequest(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrConsentRequestNotFound)
}

func TestRedisStore_ConsumeConsentRequest(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	cr := &oidc.ConsentRequest{Challenge: "consent-chal-consume", Subject: "user-1"}
	require.NoError(t, store.SaveConsentRequest(ctx, cr))

	got, err := store.ConsumeConsentRequest(ctx, "consent-chal-consume")
	require.NoError(t, err)
	assert.Equal(t, "user-1", got.Subject)

	// GETDEL semantics: second consume must fail (single-use).
	_, err = store.ConsumeConsentRequest(ctx, "consent-chal-consume")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrConsentRequestNotFound)
}

func TestRedisStore_ConsentRequest_TTLExpires(t *testing.T) {
	mr, client := newTestRedis(t)
	store := oidc.NewRedisStore(client, oidc.WithChallengeTTL(1*time.Second))
	ctx := context.Background()

	cr := &oidc.ConsentRequest{Challenge: "consent-chal-expire", Subject: "user-1"}
	require.NoError(t, store.SaveConsentRequest(ctx, cr))

	mr.FastForward(2 * time.Second)

	_, err := store.GetConsentRequest(ctx, "consent-chal-expire")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrConsentRequestNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// Authorization code tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisStore_SaveAndConsumeAuthorizationCode(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	ac := &oidc.AuthorizationCode{
		Code:                "auth-code-1",
		Subject:             "user-1",
		ClientID:            "client-1",
		RedirectURI:         "https://app.example.com/callback",
		Scopes:              []string{"openid"},
		Nonce:               "nonce-1",
		CodeChallenge:       "challenge-1",
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().UTC().Truncate(time.Second),
		ExpiresAt:           time.Now().UTC().Add(60 * time.Second).Truncate(time.Second),
	}

	require.NoError(t, store.SaveAuthorizationCode(ctx, ac))

	got, err := store.ConsumeAuthorizationCode(ctx, "auth-code-1")
	require.NoError(t, err)
	assert.Equal(t, ac, got)
}

func TestRedisStore_ConsumeAuthorizationCode_SingleUse(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	ac := &oidc.AuthorizationCode{Code: "auth-code-reuse", Subject: "user-1"}
	require.NoError(t, store.SaveAuthorizationCode(ctx, ac))

	_, err := store.ConsumeAuthorizationCode(ctx, "auth-code-reuse")
	require.NoError(t, err)

	// GETDEL semantics: reusing an authorization code must fail.
	_, err = store.ConsumeAuthorizationCode(ctx, "auth-code-reuse")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)
}

func TestRedisStore_ConsumeAuthorizationCode_NotFound(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	_, err := store.ConsumeAuthorizationCode(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)
}

func TestRedisStore_AuthorizationCode_TTLExpires(t *testing.T) {
	mr, client := newTestRedis(t)
	store := oidc.NewRedisStore(client, oidc.WithCodeTTL(1*time.Second))
	ctx := context.Background()

	ac := &oidc.AuthorizationCode{Code: "auth-code-expire", Subject: "user-1"}
	require.NoError(t, store.SaveAuthorizationCode(ctx, ac))

	mr.FastForward(2 * time.Second)

	_, err := store.ConsumeAuthorizationCode(ctx, "auth-code-expire")
	require.Error(t, err)
	assert.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)
}

func TestRedisStore_DefaultTTLs(t *testing.T) {
	mr, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()

	require.NoError(t, store.SaveLoginRequest(ctx, &oidc.LoginRequest{Challenge: "ttl-login"}))
	require.NoError(t, store.SaveConsentRequest(ctx, &oidc.ConsentRequest{Challenge: "ttl-consent"}))
	require.NoError(t, store.SaveAuthorizationCode(ctx, &oidc.AuthorizationCode{Code: "ttl-code"}))

	assert.InDelta(t, 10*time.Minute, mr.TTL("oidc:login:ttl-login"), float64(time.Second))
	assert.InDelta(t, 10*time.Minute, mr.TTL("oidc:consent:ttl-consent"), float64(time.Second))
	assert.InDelta(t, 60*time.Second, mr.TTL("oidc:code:ttl-code"), float64(time.Second))
}
