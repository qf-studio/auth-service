//go:build integration

package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateTestUser_SyntheticFallback(t *testing.T) {
	ctx := context.Background()

	// Without upstream migrations, CreateTestUser returns a synthetic fixture.
	user, err := CreateTestUser(ctx, testPG.Pool)
	require.NoError(t, err)
	assert.Equal(t, DefaultTestUserID, user.ID)
	assert.Equal(t, DefaultTestEmail, user.Email)
	assert.Equal(t, DefaultTestName, user.Name)
}

func TestCreateTestUser_WithOptions(t *testing.T) {
	ctx := context.Background()

	user, err := CreateTestUser(ctx, testPG.Pool,
		WithEmail("custom@example.com"),
		WithName("Custom User"),
		WithUserID("usr_custom_001"),
	)
	require.NoError(t, err)
	assert.Equal(t, "usr_custom_001", user.ID)
	assert.Equal(t, "custom@example.com", user.Email)
	assert.Equal(t, "Custom User", user.Name)
}

func TestCreateTestClient_SyntheticFallback(t *testing.T) {
	ctx := context.Background()

	client, err := CreateTestClient(ctx, testPG.Pool)
	require.NoError(t, err)
	assert.Equal(t, DefaultClientID, client.ID)
	assert.Equal(t, DefaultClientSecret, client.Secret)
	assert.Equal(t, DefaultClientName, client.Name)
}

func TestCreateTestTokenPair(t *testing.T) {
	ctx := context.Background()

	pair, err := CreateTestTokenPair(ctx, testPG.Pool, "usr_token_001")
	require.NoError(t, err)
	assert.Equal(t, DefaultAccessToken, pair.AccessToken)
	assert.Equal(t, DefaultRefreshToken, pair.RefreshToken)
	assert.Equal(t, "usr_token_001", pair.UserID)
}

func TestCreateTestTokenPair_DefaultUserID(t *testing.T) {
	ctx := context.Background()

	pair, err := CreateTestTokenPair(ctx, testPG.Pool, "")
	require.NoError(t, err)
	assert.Equal(t, DefaultTestUserID, pair.UserID)
}

func TestNewTestAuthResult(t *testing.T) {
	result := NewTestAuthResult()
	assert.Equal(t, DefaultAccessToken, result.AccessToken)
	assert.Equal(t, DefaultRefreshToken, result.RefreshToken)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, 3600, result.ExpiresIn)
}

func TestNewTestUserInfo(t *testing.T) {
	info := NewTestUserInfo()
	assert.Equal(t, DefaultTestUserID, info.ID)
	assert.Equal(t, DefaultTestEmail, info.Email)
	assert.Equal(t, DefaultTestName, info.Name)
}

func TestNewTestUserInfo_WithOptions(t *testing.T) {
	info := NewTestUserInfo(
		WithEmail("override@example.com"),
		WithName("Override"),
	)
	assert.Equal(t, "override@example.com", info.Email)
	assert.Equal(t, "Override", info.Name)
	assert.Equal(t, DefaultTestUserID, info.ID, "unset fields should use defaults")
}
