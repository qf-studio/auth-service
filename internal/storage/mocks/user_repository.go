package mocks

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockUserRepository is a configurable mock for storage.UserRepository.
type MockUserRepository struct {
	CreateFn          func(ctx context.Context, user *domain.User) (*domain.User, error)
	FindByIDFn        func(ctx context.Context, id string) (*domain.User, error)
	FindByEmailFn     func(ctx context.Context, email string) (*domain.User, error)
	UpdateLastLoginFn func(ctx context.Context, userID string, timestamp time.Time) error
}

// Create delegates to CreateFn.
func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	return m.CreateFn(ctx, user)
}

// FindByID delegates to FindByIDFn.
func (m *MockUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	return m.FindByIDFn(ctx, id)
}

// FindByEmail delegates to FindByEmailFn.
func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	return m.FindByEmailFn(ctx, email)
}

// UpdateLastLogin delegates to UpdateLastLoginFn.
func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID string, timestamp time.Time) error {
	return m.UpdateLastLoginFn(ctx, userID, timestamp)
}
