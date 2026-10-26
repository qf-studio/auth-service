package token_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

// refreshKey returns the encoded key part of a qf_rt_ token.
func refreshKey(t *testing.T, refreshToken string) string {
	t.Helper()
	parts := strings.SplitN(strings.TrimPrefix(refreshToken, "qf_rt_"), ".", 2)
	require.Len(t, parts, 2)
	return parts[0]
}

func activeUsers(roles ...string) *mocks.MockUserRepository {
	return &mocks.MockUserRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			return &domain.User{ID: id, Roles: roles}, nil
		},
	}
}

func TestRevokeAllRefreshTokens_InvalidatesEarlierTokensOnly(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	before, err := svc.IssueTokenPair(ctx, "user-epoch", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	other, err := svc.IssueTokenPair(ctx, "user-other", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	require.NoError(t, svc.RevokeAllRefreshTokens(ctx, "user-epoch"))

	after, err := svc.IssueTokenPair(ctx, "user-epoch", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	_, err = svc.Refresh(ctx, before.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized, "token issued before revoke-all must fail")

	_, err = svc.Refresh(ctx, after.RefreshToken)
	assert.NoError(t, err, "token issued after revoke-all must work")

	_, err = svc.Refresh(ctx, other.RefreshToken)
	assert.NoError(t, err, "other subjects are unaffected")
}

func TestRevokeAllRefreshTokens_RejectsLegacyRecordsWithoutIssueTime(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-legacy", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	require.NoError(t, mr.Set("rt_sig:"+refreshKey(t, pair.RefreshToken), "user-legacy"))

	require.NoError(t, svc.RevokeAllRefreshTokens(ctx, "user-legacy"))

	_, err = svc.Refresh(ctx, pair.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestWrappedRepository_RevokeAllForUserRevokesRedisAndPostgres(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	var dbRevokedFor string
	inner := &mocks.MockRefreshTokenRepository{
		RevokeAllForUserFn: func(_ context.Context, _ uuid.UUID, userID string) error {
			dbRevokedFor = userID
			return nil
		},
	}
	repo := svc.WrapRefreshTokenRepository(inner)

	pair, err := svc.IssueTokenPair(ctx, "user-wrap", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	require.NoError(t, repo.RevokeAllForUser(ctx, uuid.New(), "user-wrap"))
	assert.Equal(t, "user-wrap", dbRevokedFor)

	_, err = svc.Refresh(ctx, pair.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestWrappedRepository_RedisFailureIsReturned(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	inner := &mocks.MockRefreshTokenRepository{
		RevokeAllForUserFn: func(context.Context, uuid.UUID, string) error {
			t.Fatal("postgres must not be reached when redis fails")
			return nil
		},
	}
	mr.SetError("redis down")

	err := svc.WrapRefreshTokenRepository(inner).RevokeAllForUser(ctx, uuid.New(), "user-x")
	assert.Error(t, err)
}

func TestRevoke_RefreshTokenDeletesRecordAndRevokesRow(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	var dbRevokedSig string
	svc.SetRefreshTokenStore(&mocks.MockRefreshTokenRepository{
		RevokeFn: func(_ context.Context, _ uuid.UUID, sig string) error {
			dbRevokedSig = sig
			return nil
		},
	})

	pair, err := svc.IssueTokenPair(ctx, "user-revoke", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	require.NoError(t, svc.Revoke(ctx, pair.RefreshToken))

	assert.False(t, mr.Exists("rt_sig:"+refreshKey(t, pair.RefreshToken)))
	sig, ok := domain.RefreshTokenSignature(pair.RefreshToken)
	require.True(t, ok)
	assert.Equal(t, sig, dbRevokedSig)

	_, err = svc.Refresh(ctx, pair.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestRevoke_UnknownOrMalformedRefreshTokenIsNotAnError(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	for _, tok := range []string{"qf_rt_garbage", "qf_rt_a.b", "qf_rt_"} {
		assert.NoError(t, svc.Revoke(ctx, tok), tok)
	}
}

func TestRefresh_RotationConsumesToken(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-rotate", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	rotated, err := svc.Refresh(ctx, pair.RefreshToken)
	require.NoError(t, err)

	key := refreshKey(t, pair.RefreshToken)
	assert.False(t, mr.Exists("rt_sig:"+key))
	assert.True(t, mr.Exists("rt_used:"+key), "rotation leaves a tombstone")

	_, err = svc.Refresh(ctx, rotated.RefreshToken)
	assert.NoError(t, err)
}

func TestRefresh_ReuseWithinLeewayRejectsWithoutRevokingChain(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-retry", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	rotated, err := svc.Refresh(ctx, pair.RefreshToken)
	require.NoError(t, err)

	_, err = svc.Refresh(ctx, pair.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized)

	_, err = svc.Refresh(ctx, rotated.RefreshToken)
	assert.NoError(t, err, "a client retry must not end the session")
}

func TestRefresh_ReuseAfterLeewayRevokesAllTokensOfSubject(t *testing.T) {
	svc, mr := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-reuse", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	rotated, err := svc.Refresh(ctx, pair.RefreshToken)
	require.NoError(t, err)

	// Age the tombstone past the leeway.
	key := "rt_used:" + refreshKey(t, pair.RefreshToken)
	old, err := json.Marshal(map[string]any{
		"sub":     "user-reuse",
		"used_at": time.Now().Add(-time.Minute).UnixNano(),
	})
	require.NoError(t, err)
	require.NoError(t, mr.Set(key, string(old)))

	_, err = svc.Refresh(ctx, pair.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized)

	_, err = svc.Refresh(ctx, rotated.RefreshToken)
	assert.ErrorIs(t, err, api.ErrUnauthorized, "reuse must end the whole chain")
}

func TestRefresh_ConcurrentUseYieldsOnePair(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	pair, err := svc.IssueTokenPair(ctx, "user-race", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := svc.Refresh(ctx, pair.RefreshToken); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, successes)
}

func TestRefresh_InactiveUserIsRejected(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name   string
		lookup func(context.Context, uuid.UUID, string) (*domain.User, error)
	}{
		{"locked", func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			return &domain.User{ID: id, Locked: true}, nil
		}},
		{"soft deleted", func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			return &domain.User{ID: id, DeletedAt: &now}, nil
		}},
		{"not found", func(context.Context, uuid.UUID, string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		}},
		{"not found (wrapped)", func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			return nil, errors.Join(errors.New("user "+id), storage.ErrNotFound)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mr := newES256Service(t)
			ctx := context.Background()
			svc.SetUserLookup(&mocks.MockUserRepository{FindByIDFn: tt.lookup})

			pair, err := svc.IssueTokenPair(ctx, "user-inactive", nil, nil, domain.ClientTypeUser)
			require.NoError(t, err)

			_, err = svc.Refresh(ctx, pair.RefreshToken)
			assert.ErrorIs(t, err, api.ErrUnauthorized)
			assert.False(t, mr.Exists("rt_sig:"+refreshKey(t, pair.RefreshToken)),
				"the record of an inactive user is dropped")
		})
	}
}

func TestRefresh_ActiveUserGetsCurrentRoles(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()
	svc.SetUserLookup(activeUsers("editor"))

	pair, err := svc.IssueTokenPair(ctx, "user-roles", []string{"user"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	rotated, err := svc.Refresh(ctx, pair.RefreshToken)
	require.NoError(t, err)

	claims, err := svc.ValidateToken(ctx, strings.TrimPrefix(rotated.AccessToken, "qf_at_"))
	require.NoError(t, err)
	assert.Equal(t, []string{"editor"}, claims.Roles)
}
