package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mock AdminUserRepository ---

type mockAdminUserRepo struct {
	listFn       func(ctx context.Context, limit, offset int, status string) ([]*domain.User, int, error)
	findByIDFn   func(ctx context.Context, id string) (*domain.User, error)
	createFn     func(ctx context.Context, user *domain.User) (*domain.User, error)
	updateFn     func(ctx context.Context, user *domain.User) (*domain.User, error)
	softDeleteFn func(ctx context.Context, id string) error
	lockFn       func(ctx context.Context, id, reason string) (*domain.User, error)
	unlockFn     func(ctx context.Context, id string) (*domain.User, error)
}

func (m *mockAdminUserRepo) List(ctx context.Context, limit, offset int, status string) ([]*domain.User, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, limit, offset, status)
	}
	return []*domain.User{testUser()}, 1, nil
}

func (m *mockAdminUserRepo) FindByID(ctx context.Context, id string) (*domain.User, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	u := testUser()
	u.ID = id
	return u, nil
}

func (m *mockAdminUserRepo) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	if m.createFn != nil {
		return m.createFn(ctx, user)
	}
	return user, nil
}

func (m *mockAdminUserRepo) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	if m.updateFn != nil {
		return m.updateFn(ctx, user)
	}
	return user, nil
}

func (m *mockAdminUserRepo) SoftDelete(ctx context.Context, id string) error {
	if m.softDeleteFn != nil {
		return m.softDeleteFn(ctx, id)
	}
	return nil
}

func (m *mockAdminUserRepo) Lock(ctx context.Context, id, reason string) (*domain.User, error) {
	if m.lockFn != nil {
		return m.lockFn(ctx, id, reason)
	}
	u := testUser()
	u.ID = id
	u.Locked = true
	now := time.Now()
	u.LockedAt = &now
	u.LockedReason = reason
	return u, nil
}

func (m *mockAdminUserRepo) Unlock(ctx context.Context, id string) (*domain.User, error) {
	if m.unlockFn != nil {
		return m.unlockFn(ctx, id)
	}
	u := testUser()
	u.ID = id
	u.Locked = false
	return u, nil
}

// --- Mock Hasher ---

type mockHasher struct {
	hashFn   func(password string) (string, error)
	verifyFn func(password, hash string) (bool, error)
}

func (m *mockHasher) Hash(password string) (string, error) {
	if m.hashFn != nil {
		return m.hashFn(password)
	}
	return "$argon2id$mock$" + password, nil
}

func (m *mockHasher) Verify(password, hash string) (bool, error) {
	if m.verifyFn != nil {
		return m.verifyFn(password, hash)
	}
	return hash == "$argon2id$mock$"+password, nil
}

// --- Helpers ---

func testUser() *domain.User {
	now := time.Now()
	return &domain.User{
		ID:        "user-1",
		Email:     "alice@example.com",
		Name:      "Alice",
		Roles:     []string{"user"},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func newTestUserService(repo *mockAdminUserRepo) *UserService {
	return NewUserService(repo, &mockHasher{}, zap.NewNop(), audit.NopLogger{})
}

// --- ListUsers ---

func TestUserService_ListUsers(t *testing.T) {
	repo := &mockAdminUserRepo{
		listFn: func(_ context.Context, limit, offset int, status string) ([]*domain.User, int, error) {
			assert.Equal(t, 20, limit)
			assert.Equal(t, 0, offset)
			assert.Equal(t, "", status)
			return []*domain.User{testUser()}, 1, nil
		},
	}
	svc := newTestUserService(repo)

	result, err := svc.ListUsers(context.Background(), 1, 20, "")
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Users, 1)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PerPage)
}

func TestUserService_ListUsers_Pagination(t *testing.T) {
	repo := &mockAdminUserRepo{
		listFn: func(_ context.Context, limit, offset int, _ string) ([]*domain.User, int, error) {
			assert.Equal(t, 10, limit)
			assert.Equal(t, 20, offset) // page 3 * perPage 10 - 10 = 20
			return []*domain.User{}, 50, nil
		},
	}
	svc := newTestUserService(repo)

	result, err := svc.ListUsers(context.Background(), 3, 10, "")
	require.NoError(t, err)
	assert.Equal(t, 50, result.Total)
	assert.Equal(t, 3, result.Page)
}

func TestUserService_ListUsers_Error(t *testing.T) {
	repo := &mockAdminUserRepo{
		listFn: func(_ context.Context, _, _ int, _ string) ([]*domain.User, int, error) {
			return nil, 0, fmt.Errorf("db error")
		},
	}
	svc := newTestUserService(repo)

	_, err := svc.ListUsers(context.Background(), 1, 20, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// --- GetUser ---

func TestUserService_GetUser(t *testing.T) {
	svc := newTestUserService(&mockAdminUserRepo{})

	user, err := svc.GetUser(context.Background(), "user-42")
	require.NoError(t, err)
	assert.Equal(t, "user-42", user.ID)
}

func TestUserService_GetUser_NotFound(t *testing.T) {
	repo := &mockAdminUserRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestUserService(repo)

	_, err := svc.GetUser(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- CreateUser ---

func TestUserService_CreateUser(t *testing.T) {
	svc := newTestUserService(&mockAdminUserRepo{})

	req := &api.CreateUserRequest{
		Email:    "new@example.com",
		Password: "super-secure-password",
		Name:     "New User",
	}
	user, err := svc.CreateUser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", user.Email)
	assert.Equal(t, "New User", user.Name)
	assert.Equal(t, []string{"user"}, user.Roles) // default role
}

func TestUserService_CreateUser_DuplicateEmail(t *testing.T) {
	repo := &mockAdminUserRepo{
		createFn: func(_ context.Context, _ *domain.User) (*domain.User, error) {
			return nil, fmt.Errorf("dup: %w", storage.ErrDuplicateEmail)
		},
	}
	svc := newTestUserService(repo)

	_, err := svc.CreateUser(context.Background(), &api.CreateUserRequest{
		Email:    "dup@example.com",
		Password: "super-secure-password",
		Name:     "Dup",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

func TestUserService_CreateUser_HashError(t *testing.T) {
	svc := NewUserService(&mockAdminUserRepo{}, &mockHasher{
		hashFn: func(_ string) (string, error) {
			return "", fmt.Errorf("hash failed")
		},
	}, zap.NewNop(), audit.NopLogger{})

	_, err := svc.CreateUser(context.Background(), &api.CreateUserRequest{
		Email:    "new@example.com",
		Password: "password",
		Name:     "Test",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// --- UpdateUser ---

func TestUserService_UpdateUser(t *testing.T) {
	svc := newTestUserService(&mockAdminUserRepo{})

	name := "Updated Name"
	user, err := svc.UpdateUser(context.Background(), "user-1", &api.UpdateUserRequest{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", user.Name)
}

func TestUserService_UpdateUser_NotFound(t *testing.T) {
	repo := &mockAdminUserRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestUserService(repo)

	name := "Nope"
	_, err := svc.UpdateUser(context.Background(), "nonexistent", &api.UpdateUserRequest{Name: &name})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- DeleteUser ---

func TestUserService_DeleteUser(t *testing.T) {
	svc := newTestUserService(&mockAdminUserRepo{})

	err := svc.DeleteUser(context.Background(), "user-1")
	require.NoError(t, err)
}

func TestUserService_DeleteUser_NotFound(t *testing.T) {
	repo := &mockAdminUserRepo{
		softDeleteFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("not found: %w", storage.ErrNotFound)
		},
	}
	svc := newTestUserService(repo)

	err := svc.DeleteUser(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestUserService_DeleteUser_AlreadyDeleted(t *testing.T) {
	repo := &mockAdminUserRepo{
		softDeleteFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("already deleted: %w", storage.ErrAlreadyDeleted)
		},
	}
	svc := newTestUserService(repo)

	err := svc.DeleteUser(context.Background(), "deleted-user")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- LockUser ---

func TestUserService_LockUser(t *testing.T) {
	svc := newTestUserService(&mockAdminUserRepo{})

	user, err := svc.LockUser(context.Background(), "user-1", "suspicious activity")
	require.NoError(t, err)
	assert.True(t, user.Locked)
	assert.Equal(t, "suspicious activity", user.LockedReason)
}

func TestUserService_LockUser_NotFound(t *testing.T) {
	repo := &mockAdminUserRepo{
		lockFn: func(_ context.Context, _, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("not found: %w", storage.ErrNotFound)
		},
	}
	svc := newTestUserService(repo)

	_, err := svc.LockUser(context.Background(), "nonexistent", "reason")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- UnlockUser ---

func TestUserService_UnlockUser(t *testing.T) {
	svc := newTestUserService(&mockAdminUserRepo{})

	user, err := svc.UnlockUser(context.Background(), "user-1")
	require.NoError(t, err)
	assert.False(t, user.Locked)
}

func TestUserService_UnlockUser_NotFound(t *testing.T) {
	repo := &mockAdminUserRepo{
		unlockFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("not found: %w", storage.ErrNotFound)
		},
	}
	svc := newTestUserService(repo)

	_, err := svc.UnlockUser(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- domainUserToAdmin ---

func TestDomainUserToAdmin(t *testing.T) {
	now := time.Now()
	u := &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		Name:         "Alice",
		Roles:        []string{"admin", "user"},
		Locked:       true,
		LockedAt:     &now,
		LockedReason: "test reason",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	admin := domainUserToAdmin(u)
	assert.Equal(t, "user-1", admin.ID)
	assert.Equal(t, "alice@example.com", admin.Email)
	assert.Equal(t, "Alice", admin.Name)
	assert.Equal(t, []string{"admin", "user"}, admin.Roles)
	assert.True(t, admin.Locked)
	assert.Equal(t, &now, admin.LockedAt)
	assert.Equal(t, "test reason", admin.LockedReason)
}
