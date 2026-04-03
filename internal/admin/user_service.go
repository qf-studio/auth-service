package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

// UserService implements api.AdminUserService for admin user management.
type UserService struct {
	repo   UserRepository
	hasher password.Hasher
}

// NewUserService creates a new admin UserService.
func NewUserService(repo UserRepository, hasher password.Hasher) *UserService {
	return &UserService{repo: repo, hasher: hasher}
}

// ListUsers returns a paginated list of users.
func (s *UserService) ListUsers(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminUserList, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}

	offset := (page - 1) * perPage

	users, total, err := s.repo.FindAll(ctx, offset, perPage, includeDeleted)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}

	result := make([]api.AdminUser, len(users))
	for i, u := range users {
		result[i] = domainUserToAdminUser(u)
	}

	return &api.AdminUserList{
		Users:   result,
		Total:   int(total),
		Page:    page,
		PerPage: perPage,
	}, nil
}

// GetUser returns a single user by ID.
func (s *UserService) GetUser(ctx context.Context, userID string) (*api.AdminUser, error) {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("get user: %w", err)
	}

	result := domainUserToAdminUser(user)
	return &result, nil
}

// CreateUser creates a new user with a hashed password.
func (s *UserService) CreateUser(ctx context.Context, req *api.CreateUserRequest) (*api.AdminUser, error) {
	hash, err := s.hasher.Hash(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	roles := req.Roles
	if len(roles) == 0 {
		roles = []string{"user"}
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		PasswordHash: hash,
		Name:         req.Name,
		Roles:        roles,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	created, err := s.repo.Create(ctx, user)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("email %s already exists: %w", req.Email, api.ErrConflict)
		}
		return nil, fmt.Errorf("create user: %w", err)
	}

	result := domainUserToAdminUser(created)
	return &result, nil
}

// UpdateUser applies partial field updates to an existing user.
func (s *UserService) UpdateUser(ctx context.Context, userID string, req *api.UpdateUserRequest) (*api.AdminUser, error) {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("get user for update: %w", err)
	}

	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Roles != nil {
		user.Roles = req.Roles
	}
	user.UpdatedAt = time.Now().UTC()

	updated, err := s.repo.Update(ctx, user)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("update user: %w", err)
	}

	result := domainUserToAdminUser(updated)
	return &result, nil
}

// DeleteUser soft-deletes a user by setting their deleted_at timestamp.
// Returns api.ErrConflict if the user is already deleted.
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		return fmt.Errorf("get user for delete: %w", err)
	}

	if user.DeletedAt != nil {
		return fmt.Errorf("user %s already deleted: %w", userID, api.ErrConflict)
	}

	if err := s.repo.SoftDelete(ctx, userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		return fmt.Errorf("delete user: %w", err)
	}

	return nil
}

// LockUser locks a user account with the given reason.
func (s *UserService) LockUser(ctx context.Context, userID string, reason string) (*api.AdminUser, error) {
	now := time.Now().UTC()

	if err := s.repo.SetLocked(ctx, userID, true, reason, &now); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("lock user: %w", err)
	}

	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user after lock: %w", err)
	}

	result := domainUserToAdminUser(user)
	return &result, nil
}

// UnlockUser removes the lock on a user account.
func (s *UserService) UnlockUser(ctx context.Context, userID string) (*api.AdminUser, error) {
	if err := s.repo.SetLocked(ctx, userID, false, "", nil); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("unlock user: %w", err)
	}

	user, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user after unlock: %w", err)
	}

	result := domainUserToAdminUser(user)
	return &result, nil
}

// domainUserToAdminUser maps a domain.User to the api.AdminUser response type.
func domainUserToAdminUser(u *domain.User) api.AdminUser {
	return api.AdminUser{
		ID:           u.ID,
		Email:        u.Email,
		Name:         u.Name,
		Roles:        u.Roles,
		Locked:       u.Locked,
		LockedAt:     u.LockedAt,
		LockedReason: u.LockedReason,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
		DeletedAt:    u.DeletedAt,
	}
}

// Compile-time assertion.
var _ api.AdminUserService = (*UserService)(nil)
