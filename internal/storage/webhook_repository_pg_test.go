package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPostgresWebhookRepository_ImplementsInterface(t *testing.T) {
	// Compile-time check that PostgresWebhookRepository satisfies WebhookRepository.
	var _ WebhookRepository = (*PostgresWebhookRepository)(nil)
}

func TestNewPostgresWebhookRepository(t *testing.T) {
	repo := NewPostgresWebhookRepository(nil)
	assert.NotNil(t, repo)
	assert.Nil(t, repo.pool)
}
