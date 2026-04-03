package client

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Repository defines the persistence operations for OAuth2 clients.
type Repository interface {
	Create(ctx context.Context, client *domain.Client) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	GetByName(ctx context.Context, name string) (*domain.Client, error)
	List(ctx context.Context, owner string) ([]*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
}
