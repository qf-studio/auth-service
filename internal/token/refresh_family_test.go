package token_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

// storedFamilyID reads the family id off the live record for refreshToken.
func storedFamilyID(t *testing.T, svcRedisGet func(key string) (string, error), refreshToken string) string {
	t.Helper()
	raw, err := svcRedisGet("rt_sig:" + refreshKey(t, refreshToken))
	require.NoError(t, err)
	var rec struct {
		FamilyID string `json:"fid"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &rec))
	return rec.FamilyID
}

func TestIssueTokenPair_SetsFamilyIDAndTokenIdentifiers(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	a, err := svc.IssueTokenPair(ctx, "user-fam", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	b, err := svc.IssueTokenPair(ctx, "user-fam", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	require.NotEmpty(t, a.RefreshFamilyID)
	assert.NotEqual(t, a.RefreshFamilyID, b.RefreshFamilyID, "each new pair starts its own family")
	assert.Equal(t, a.RefreshFamilyID, storedFamilyID(t, mr.Get, a.RefreshToken), "family id is stored on the record")

	claims, err := svc.ValidateToken(ctx, a.AccessToken[len("qf_at_"):])
	require.NoError(t, err)
	assert.Equal(t, claims.TokenID, a.AccessTokenID)
	assert.WithinDuration(t, claims.ExpiresAt, a.AccessTokenExpiresAt, time.Second)
}

func TestIssueAccessTokenForClient_ReturnsJTIWithoutFamily(t *testing.T) {
	svc, _ := newES256Service(t)

	res, err := svc.IssueAccessTokenForClient(context.Background(), "user-at", nil, nil, domain.ClientTypeUser, "client-1")
	require.NoError(t, err)
	assert.NotEmpty(t, res.AccessTokenID)
	assert.False(t, res.AccessTokenExpiresAt.IsZero())
	assert.Empty(t, res.RefreshFamilyID)
}

func TestRefresh_RotationKeepsFamilyID(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	first, err := svc.IssueTokenPair(ctx, "user-rot", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	second, err := svc.Refresh(ctx, first.RefreshToken)
	require.NoError(t, err)
	third, err := svc.Refresh(ctx, second.RefreshToken)
	require.NoError(t, err)

	assert.Equal(t, first.RefreshFamilyID, second.RefreshFamilyID)
	assert.Equal(t, first.RefreshFamilyID, third.RefreshFamilyID)
	assert.Equal(t, first.RefreshFamilyID, storedFamilyID(t, mr.Get, third.RefreshToken))
}

func TestRevokeRefreshFamily_RevokesRotatedSuccessorsOnly(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	family, err := svc.IssueTokenPair(ctx, "user-famrev", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	// Rotate twice: the original key is gone, only the successor is live.
	rotated, err := svc.Refresh(ctx, family.RefreshToken)
	require.NoError(t, err)
	successor, err := svc.Refresh(ctx, rotated.RefreshToken)
	require.NoError(t, err)

	otherFamily, err := svc.IssueTokenPair(ctx, "user-famrev", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	require.NoError(t, svc.RevokeRefreshFamily(ctx, family.RefreshFamilyID))

	_, err = svc.Refresh(ctx, successor.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized, "rotated successor of the revoked family must fail")

	_, err = svc.Refresh(ctx, otherFamily.RefreshToken)
	assert.NoError(t, err, "another family of the same user keeps working")
}

func TestRevokeRefreshFamily_RevokesLiveToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-famlive", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	require.NoError(t, svc.RevokeRefreshFamily(ctx, pair.RefreshFamilyID))

	_, err = svc.Refresh(ctx, pair.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestRevokeRefreshFamily_SetsMarkerWithRefreshTTL(t *testing.T) {
	svc, mr := newES256Service(t)

	require.NoError(t, svc.RevokeRefreshFamily(context.Background(), "fam-ttl"))

	assert.True(t, mr.Exists("rt_fam_revoked:fam-ttl"))
	assert.Equal(t, defaultCfg().RefreshTokenTTL, mr.TTL("rt_fam_revoked:fam-ttl"))
}

func TestRevokeRefreshFamily_EmptyFamilyIsAnError(t *testing.T) {
	svc, _ := newES256Service(t)
	assert.Error(t, svc.RevokeRefreshFamily(context.Background(), ""))
}

func TestRefresh_LegacyRecordWithoutFamilyStillRotates(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-legacyfam", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	legacy, err := json.Marshal(map[string]any{"sub": "user-legacyfam", "iat": time.Now().UnixNano()})
	require.NoError(t, err)
	require.NoError(t, mr.Set("rt_sig:"+refreshKey(t, pair.RefreshToken), string(legacy)))

	next, err := svc.Refresh(ctx, pair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, next.RefreshFamilyID, "rotation of a pre-family record starts a family")
}

func TestRevokeJTI_MakesIsRevokedTrue(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-jti", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	revoked, err := svc.IsRevoked(ctx, pair.AccessTokenID)
	require.NoError(t, err)
	require.False(t, revoked)

	require.NoError(t, svc.RevokeJTI(ctx, pair.AccessTokenID, pair.AccessTokenExpiresAt))

	revoked, err = svc.IsRevoked(ctx, pair.AccessTokenID)
	require.NoError(t, err)
	assert.True(t, revoked)
	assert.Positive(t, mr.TTL("revoked:"+pair.AccessTokenID), "entry lives for the token's remaining lifetime")

	other, err := svc.IssueTokenPair(ctx, "user-jti", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	revoked, err = svc.IsRevoked(ctx, other.AccessTokenID)
	require.NoError(t, err)
	assert.False(t, revoked, "other tokens of the same user are unaffected")
}

func TestRevokeJTI_ExpiredTokenWritesNothingAndEmptyJTIFails(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	require.NoError(t, svc.RevokeJTI(ctx, "jti-expired", time.Now().Add(-time.Minute)))
	assert.False(t, mr.Exists("revoked:jti-expired"))

	assert.Error(t, svc.RevokeJTI(ctx, "", time.Now().Add(time.Minute)))
}
