package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

func TestService_Create(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	wh, err := svc.Create(context.Background(), CreateInput{
		URL:        "https://example.com/hook",
		EventTypes: []string{domain.WebhookEventUserCreated, domain.WebhookEventUserDeleted},
	})
	require.NoError(t, err)
	require.NotNil(t, wh)

	assert.NotEmpty(t, wh.ID)
	assert.Equal(t, "https://example.com/hook", wh.URL)
	assert.NotEmpty(t, wh.Secret)
	assert.Len(t, wh.Secret, 64) // 32 bytes hex-encoded
	assert.True(t, wh.Active)
	assert.Equal(t, 0, wh.FailureCount)
	assert.Equal(t, []string{domain.WebhookEventUserCreated, domain.WebhookEventUserDeleted}, wh.EventTypes)
	assert.False(t, wh.CreatedAt.IsZero())
	assert.False(t, wh.UpdatedAt.IsZero())
}

func TestService_Get(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	created, err := svc.Create(context.Background(), CreateInput{
		URL:        "https://example.com/get",
		EventTypes: []string{domain.WebhookEventUserCreated},
	})
	require.NoError(t, err)

	got, err := svc.Get(context.Background(), created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, created.URL, got.URL)
}

func TestService_Get_NotFound(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	got, err := svc.Get(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestService_List(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	_, err := svc.Create(context.Background(), CreateInput{
		URL:        "https://example.com/1",
		EventTypes: []string{domain.WebhookEventUserCreated},
	})
	require.NoError(t, err)

	_, err = svc.Create(context.Background(), CreateInput{
		URL:        "https://example.com/2",
		EventTypes: []string{domain.WebhookEventUserDeleted},
	})
	require.NoError(t, err)

	webhooks, err := svc.List(context.Background(), false)
	require.NoError(t, err)
	assert.Len(t, webhooks, 2)
}

func TestService_Update(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	created, err := svc.Create(context.Background(), CreateInput{
		URL:        "https://example.com/old",
		EventTypes: []string{domain.WebhookEventUserCreated},
	})
	require.NoError(t, err)

	newURL := "https://example.com/new"
	newActive := false
	updated, err := svc.Update(context.Background(), created.ID, UpdateInput{
		URL:        &newURL,
		EventTypes: []string{domain.WebhookEventUserDeleted},
		Active:     &newActive,
	})
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/new", updated.URL)
	assert.Equal(t, []string{domain.WebhookEventUserDeleted}, updated.EventTypes)
	assert.False(t, updated.Active)
}

func TestService_Update_NotFound(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	newURL := "https://example.com/new"
	_, err := svc.Update(context.Background(), "nonexistent", UpdateInput{
		URL: &newURL,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestService_Delete(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	created, err := svc.Create(context.Background(), CreateInput{
		URL:        "https://example.com/delete",
		EventTypes: []string{domain.WebhookEventUserCreated},
	})
	require.NoError(t, err)

	err = svc.Delete(context.Background(), created.ID)
	require.NoError(t, err)

	// Verify it's gone from the mock.
	got, err := svc.Get(context.Background(), created.ID)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestService_Delete_NotFound(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	svc := NewService(logger, repo)

	err := svc.Delete(context.Background(), "nonexistent")
	require.NoError(t, err) // mock doesn't error on missing
}

// Verify Service uses the WebhookRepository interface.
var _ storage.WebhookRepository = (*mockWebhookRepo)(nil)
