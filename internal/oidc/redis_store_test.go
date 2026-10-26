package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// ────────────────────────────────────────────────────────────────────────────
// Used-code records (GH-542)
// ────────────────────────────────────────────────────────────────────────────

func usedKeyFor(code string) string {
	sum := sha256.Sum256([]byte(code))
	return "oidc_code_used:" + hex.EncodeToString(sum[:])
}

func seedCode(t *testing.T, store *oidc.RedisStore, code string) {
	t.Helper()
	require.NoError(t, store.SaveAuthorizationCode(context.Background(), &oidc.AuthorizationCode{
		Code:     code,
		Subject:  "user-1",
		ClientID: "client-1",
	}))
}

func TestRedisStore_ConsumeAuthorizationCode_WritesHashedUsedRecord(t *testing.T) {
	mr, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	seedCode(t, store, "code-hash-me")

	_, err := store.ConsumeAuthorizationCode(context.Background(), "code-hash-me")
	require.NoError(t, err)

	key := usedKeyFor("code-hash-me")
	assert.True(t, mr.Exists(key))
	assert.GreaterOrEqual(t, mr.TTL(key), 15*time.Minute)
	for _, k := range mr.Keys() {
		assert.NotContains(t, k, "code-hash-me", "the raw code must not appear in any key")
	}
}

func TestRedisStore_ConsumeAuthorizationCode_UnknownCodeWritesNoRecord(t *testing.T) {
	mr, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)

	_, err := store.ConsumeAuthorizationCode(context.Background(), "never-issued")
	require.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)

	assert.Empty(t, mr.Keys(), "presenting an unknown code must not create state")
}

func TestRedisStore_WithUsedCodeTTL(t *testing.T) {
	mr, client := newTestRedis(t)
	store := oidc.NewRedisStore(client, oidc.WithUsedCodeTTL(time.Hour))
	seedCode(t, store, "code-ttl")

	_, err := store.ConsumeAuthorizationCode(context.Background(), "code-ttl")
	require.NoError(t, err)
	assert.Equal(t, time.Hour, mr.TTL(usedKeyFor("code-ttl")))

	// A value below the floor is ignored.
	mr2, client2 := newTestRedis(t)
	short := oidc.NewRedisStore(client2, oidc.WithUsedCodeTTL(time.Minute))
	seedCode(t, short, "code-floor")
	_, err = short.ConsumeAuthorizationCode(context.Background(), "code-floor")
	require.NoError(t, err)
	assert.Equal(t, 15*time.Minute, mr2.TTL(usedKeyFor("code-floor")))
}

func TestRedisStore_MarkCodeReplayed_UnknownCode(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)

	_, err := store.MarkCodeReplayed(context.Background(), "never-redeemed")
	assert.ErrorIs(t, err, oidc.ErrUsedCodeNotFound)
}

func TestRedisStore_RecordCodeIssuance_NoRecord(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)

	_, err := store.RecordCodeIssuance(context.Background(), "never-redeemed", oidc.CodeIssuance{AccessTokenID: "jti"})
	assert.ErrorIs(t, err, oidc.ErrUsedCodeNotFound)
}

func TestRedisStore_RecordThenReplay_ReturnsIssuance(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()
	seedCode(t, store, "code-rr")
	_, err := store.ConsumeAuthorizationCode(ctx, "code-rr")
	require.NoError(t, err)

	exp := time.Now().Add(15 * time.Minute).Truncate(time.Second)
	replayed, err := store.RecordCodeIssuance(ctx, "code-rr", oidc.CodeIssuance{
		AccessTokenID: "jti-1", AccessTokenExpiresAt: exp, RefreshFamilyID: "fam-1",
	})
	require.NoError(t, err)
	assert.False(t, replayed)

	got, err := store.MarkCodeReplayed(ctx, "code-rr")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "jti-1", got.AccessTokenID)
	assert.Equal(t, "fam-1", got.RefreshFamilyID)
	assert.True(t, exp.Equal(got.AccessTokenExpiresAt))
}

func TestRedisStore_RecordWithoutFamily_RoundTripsEmptyFamily(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()
	seedCode(t, store, "code-nofam")
	_, err := store.ConsumeAuthorizationCode(ctx, "code-nofam")
	require.NoError(t, err)

	_, err = store.RecordCodeIssuance(ctx, "code-nofam", oidc.CodeIssuance{
		AccessTokenID: "jti-2", AccessTokenExpiresAt: time.Now().Add(time.Minute),
	})
	require.NoError(t, err)

	got, err := store.MarkCodeReplayed(ctx, "code-nofam")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "jti-2", got.AccessTokenID)
	assert.Empty(t, got.RefreshFamilyID)
}

// TestRedisStore_ReplayBeforeIssuanceDetails covers the race with the first
// redemption: the replay finds no details, flags the record, and the first
// redemption's RecordCodeIssuance then reports it so it can revoke its tokens.
func TestRedisStore_ReplayBeforeIssuanceDetails(t *testing.T) {
	_, client := newTestRedis(t)
	store := oidc.NewRedisStore(client)
	ctx := context.Background()
	seedCode(t, store, "code-race")
	_, err := store.ConsumeAuthorizationCode(ctx, "code-race")
	require.NoError(t, err)

	got, err := store.MarkCodeReplayed(ctx, "code-race")
	require.NoError(t, err)
	assert.Nil(t, got, "no issuance recorded yet")

	replayed, err := store.RecordCodeIssuance(ctx, "code-race", oidc.CodeIssuance{
		AccessTokenID: "jti-race", AccessTokenExpiresAt: time.Now().Add(time.Minute), RefreshFamilyID: "fam-race",
	})
	require.NoError(t, err)
	assert.True(t, replayed)
}
