package mocks

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockUserRepository is a configurable mock for storage.UserRepository.
type MockUserRepository struct {
	CreateFn                  func(ctx context.Context, user *domain.User) (*domain.User, error)
	FindByIDFn                func(ctx context.Context, id string) (*domain.User, error)
	FindByEmailFn             func(ctx context.Context, email string) (*domain.User, error)
	UpdateLastLoginFn         func(ctx context.Context, userID string, timestamp time.Time) error
	SetEmailVerifyTokenFn     func(ctx context.Context, userID string, token string, expiresAt time.Time) error
	ConsumeEmailVerifyTokenFn func(ctx context.Context, token string) (*domain.User, error)
	SetForcePasswordChangeFn  func(ctx context.Context, userID string, force bool) error
	ListActiveUserIDsFn       func(ctx context.Context, limit, offset int) ([]string, error)
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

// SetEmailVerifyToken delegates to SetEmailVerifyTokenFn.
func (m *MockUserRepository) SetEmailVerifyToken(ctx context.Context, userID string, token string, expiresAt time.Time) error {
	return m.SetEmailVerifyTokenFn(ctx, userID, token, expiresAt)
}

// ConsumeEmailVerifyToken delegates to ConsumeEmailVerifyTokenFn.
func (m *MockUserRepository) ConsumeEmailVerifyToken(ctx context.Context, token string) (*domain.User, error) {
	return m.ConsumeEmailVerifyTokenFn(ctx, token)
}

// SetForcePasswordChange delegates to SetForcePasswordChangeFn.
func (m *MockUserRepository) SetForcePasswordChange(ctx context.Context, userID string, force bool) error {
	if m.SetForcePasswordChangeFn != nil {
		return m.SetForcePasswordChangeFn(ctx, userID, force)
	}
	return nil
}

// ListActiveUserIDs delegates to ListActiveUserIDsFn.
func (m *MockUserRepository) ListActiveUserIDs(ctx context.Context, limit, offset int) ([]string, error) {
	if m.ListActiveUserIDsFn != nil {
		return m.ListActiveUserIDsFn(ctx, limit, offset)
	}
	return nil, nil
}
