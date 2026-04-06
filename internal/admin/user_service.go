// Package admin implements admin-facing service operations for user management,
// client management, and token introspection.
package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

// UserService implements api.AdminUserService.
type UserService struct {
	repo      storage.AdminUserRepository
	auditRepo storage.AuditReadRepository
	hasher    password.Hasher
	logger    *zap.Logger
	audit     audit.EventLogger
}

// NewUserService creates a new admin user service.
func NewUserService(repo storage.AdminUserRepository, hasher password.Hasher, logger *zap.Logger, auditor audit.EventLogger) *UserService {
	return &UserService{
		repo:   repo,
		hasher: hasher,
		logger: logger,
		audit:  auditor,
	}
}

// SetAuditReadRepo sets the audit read repository for activity timeline queries.
func (s *UserService) SetAuditReadRepo(repo storage.AuditReadRepository) {
	s.auditRepo = repo
}

// ListUsers returns a paginated list of users filtered by status.
func (s *UserService) ListUsers(ctx context.Context, page, perPage int, status string) (*api.AdminUserList, error) {
	offset := (page - 1) * perPage

	users, total, err := s.repo.List(ctx, perPage, offset, status)
	if err != nil {
		s.logger.Error("list users failed", zap.Error(err))
		return nil, fmt.Errorf("list users: %w", api.ErrInternalError)
	}

	result := &api.AdminUserList{
		Users:   make([]api.AdminUser, 0, len(users)),
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	for _, u := range users {
		result.Users = append(result.Users, domainUserToAdmin(u))
	}

	return result, nil
}

// GetUser retrieves a single user by ID.
func (s *UserService) GetUser(ctx context.Context, userID string) (*api.AdminUser, error) {
	u, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		s.logger.Error("get user failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("get user: %w", api.ErrInternalError)
	}

	admin := domainUserToAdmin(u)
	return &admin, nil
}

// CreateUser creates a new user with a hashed password.
func (s *UserService) CreateUser(ctx context.Context, req *api.CreateUserRequest) (*api.AdminUser, error) {
	hash, err := s.hasher.Hash(req.Password)
	if err != nil {
		s.logger.Error("password hash failed", zap.Error(err))
		return nil, fmt.Errorf("create user: %w", api.ErrInternalError)
	}

	now := time.Now().UTC()
	roles := req.Roles
	if roles == nil {
		roles = []string{"user"}
	}

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
			return nil, fmt.Errorf("email already exists: %w", api.ErrConflict)
		}
		s.logger.Error("create user failed", zap.Error(err))
		return nil, fmt.Errorf("create user: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminUserCreate,
		TargetID: created.ID,
		Metadata: map[string]string{"email": created.Email},
	})

	admin := domainUserToAdmin(created)
	return &admin, nil
}

// UpdateUser modifies user fields.
func (s *UserService) UpdateUser(ctx context.Context, userID string, req *api.UpdateUserRequest) (*api.AdminUser, error) {
	existing, err := s.repo.FindByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		s.logger.Error("find user for update failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("update user: %w", api.ErrInternalError)
	}

	if req.Email != nil {
		existing.Email = *req.Email
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Roles != nil {
		existing.Roles = req.Roles
	}

	updated, err := s.repo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("email already exists: %w", api.ErrConflict)
		}
		s.logger.Error("update user failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("update user: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminUserUpdate,
		TargetID: userID,
	})

	admin := domainUserToAdmin(updated)
	return &admin, nil
}

// DeleteUser performs a soft delete.
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	err := s.repo.SoftDelete(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrAlreadyDeleted) {
			return fmt.Errorf("user %s already deleted: %w", userID, api.ErrConflict)
		}
		s.logger.Error("delete user failed", zap.String("user_id", userID), zap.Error(err))
		return fmt.Errorf("delete user: %w", api.ErrInternalError)
	}
	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminUserDelete,
		TargetID: userID,
	})
	return nil
}

// LockUser locks a user account with a reason.
func (s *UserService) LockUser(ctx context.Context, userID string, reason string) (*api.AdminUser, error) {
	u, err := s.repo.Lock(ctx, userID, reason)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		s.logger.Error("lock user failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("lock user: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminUserLock,
		TargetID: userID,
		Metadata: map[string]string{"reason": reason},
	})

	admin := domainUserToAdmin(u)
	return &admin, nil
}

// UnlockUser removes the lock from a user account.
func (s *UserService) UnlockUser(ctx context.Context, userID string) (*api.AdminUser, error) {
	u, err := s.repo.Unlock(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		s.logger.Error("unlock user failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("unlock user: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminUserUnlock,
		TargetID: userID,
	})

	admin := domainUserToAdmin(u)
	return &admin, nil
}

// SearchUsers returns a paginated list of users matching the given filters.
func (s *UserService) SearchUsers(ctx context.Context, page, perPage int, email, role, status string, createdAfter, createdBefore *time.Time) (*api.AdminUserList, error) {
	offset := (page - 1) * perPage

	filter := storage.UserSearchFilter{
		Email:         email,
		Role:          role,
		Status:        status,
		CreatedAfter:  createdAfter,
		CreatedBefore: createdBefore,
	}

	users, total, err := s.repo.SearchUsers(ctx, perPage, offset, filter)
	if err != nil {
		s.logger.Error("search users failed", zap.Error(err))
		return nil, fmt.Errorf("search users: %w", api.ErrInternalError)
	}

	result := &api.AdminUserList{
		Users:   make([]api.AdminUser, 0, len(users)),
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}
	for _, u := range users {
		result.Users = append(result.Users, domainUserToAdmin(u))
	}
	return result, nil
}

// BulkLock locks multiple user accounts at once.
func (s *UserService) BulkLock(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
	affected, err := s.repo.BulkUpdateStatus(ctx, req.UserIDs, "lock", req.Reason)
	if err != nil {
		s.logger.Error("bulk lock failed", zap.Error(err))
		return nil, fmt.Errorf("bulk lock: %w", api.ErrInternalError)
	}
	for _, id := range req.UserIDs {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventAdminUserLock,
			TargetID: id,
			Metadata: map[string]string{"reason": req.Reason, "bulk": "true"},
		})
	}
	return &api.BulkActionResult{Affected: affected}, nil
}

// BulkUnlock unlocks multiple user accounts at once.
func (s *UserService) BulkUnlock(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
	affected, err := s.repo.BulkUpdateStatus(ctx, req.UserIDs, "unlock", "")
	if err != nil {
		s.logger.Error("bulk unlock failed", zap.Error(err))
		return nil, fmt.Errorf("bulk unlock: %w", api.ErrInternalError)
	}
	for _, id := range req.UserIDs {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventAdminUserUnlock,
			TargetID: id,
			Metadata: map[string]string{"bulk": "true"},
		})
	}
	return &api.BulkActionResult{Affected: affected}, nil
}

// BulkSuspend soft-deletes multiple user accounts at once.
func (s *UserService) BulkSuspend(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
	affected, err := s.repo.BulkUpdateStatus(ctx, req.UserIDs, "suspend", req.Reason)
	if err != nil {
		s.logger.Error("bulk suspend failed", zap.Error(err))
		return nil, fmt.Errorf("bulk suspend: %w", api.ErrInternalError)
	}
	for _, id := range req.UserIDs {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventAdminUserDelete,
			TargetID: id,
			Metadata: map[string]string{"reason": req.Reason, "bulk": "true"},
		})
	}
	return &api.BulkActionResult{Affected: affected}, nil
}

// BulkAssignRole assigns a role to multiple users at once.
func (s *UserService) BulkAssignRole(ctx context.Context, req *api.BulkAssignRoleRequest) (*api.BulkActionResult, error) {
	affected, err := s.repo.BulkAssignRole(ctx, req.UserIDs, req.Role)
	if err != nil {
		s.logger.Error("bulk assign role failed", zap.Error(err))
		return nil, fmt.Errorf("bulk assign role: %w", api.ErrInternalError)
	}
	for _, id := range req.UserIDs {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventAdminUserUpdate,
			TargetID: id,
			Metadata: map[string]string{"role_assigned": req.Role, "bulk": "true"},
		})
	}
	return &api.BulkActionResult{Affected: affected}, nil
}

// GetActivity returns the audit activity timeline for a specific user.
func (s *UserService) GetActivity(ctx context.Context, userID string, page, perPage int) (*api.UserActivityTimeline, error) {
	if s.auditRepo == nil {
		return nil, fmt.Errorf("activity timeline not available: %w", api.ErrInternalError)
	}

	// Verify user exists.
	if _, err := s.repo.FindByID(ctx, userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		s.logger.Error("find user for activity failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("get activity: %w", api.ErrInternalError)
	}

	offset := (page - 1) * perPage
	entries, total, err := s.auditRepo.ListByTargetID(ctx, userID, perPage, offset)
	if err != nil {
		s.logger.Error("get user activity failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("get activity: %w", api.ErrInternalError)
	}

	events := make([]api.UserActivityEntry, 0, len(entries))
	for _, e := range entries {
		events = append(events, api.UserActivityEntry{
			ID:        e.ID,
			EventType: e.EventType,
			ActorID:   e.ActorID,
			IP:        e.IP,
			Metadata:  e.Metadata,
			CreatedAt: e.CreatedAt,
		})
	}

	return &api.UserActivityTimeline{
		Events:  events,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}, nil
}

// domainUserToAdmin converts a domain.User to an api.AdminUser response DTO.
func domainUserToAdmin(u *domain.User) api.AdminUser {
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
