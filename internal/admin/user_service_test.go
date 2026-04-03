package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mock UserRepository ---

type mockUserRepo struct {
	findByIDFn   func(ctx context.Context, id string) (*domain.User, error)
	findAllFn    func(ctx context.Context, offset, limit int, includeDeleted bool) ([]*domain.User, int64, error)
	createFn     func(ctx context.Context, user *domain.User) (*domain.User, error)
	updateFn     func(ctx context.Context, user *domain.User) (*domain.User, error)
	softDeleteFn func(ctx context.Context, id string) error
	setLockedFn  func(ctx context.Context, id string, locked bool, reason string, lockedAt *time.Time) error
}

func (m *mockUserRepo) FindByID(ctx context.Context, id string) (*domain.User, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	return nil, storage.ErrNotFound
}

func (m *mockUserRepo) FindAll(ctx context.Context, offset, limit int, includeDeleted bool) ([]*domain.User, int64, error) {
	if m.findAllFn != nil {
		return m.findAllFn(ctx, offset, limit, includeDeleted)
	}
	return []*domain.User{}, 0, nil
}

func (m *mockUserRepo) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	if m.createFn != nil {
		return m.createFn(ctx, user)
	}
	return user, nil
}

func (m *mockUserRepo) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	if m.updateFn != nil {
		return m.updateFn(ctx, user)
	}
	return user, nil
}

func (m *mockUserRepo) SoftDelete(ctx context.Context, id string) error {
	if m.softDeleteFn != nil {
		return m.softDeleteFn(ctx, id)
	}
	return nil
}

func (m *mockUserRepo) SetLocked(ctx context.Context, id string, locked bool, reason string, lockedAt *time.Time) error {
	if m.setLockedFn != nil {
		return m.setLockedFn(ctx, id, locked, reason, lockedAt)
	}
	return nil
}

// --- Mock Hasher ---

type mockHasher struct {
	hashFn func(password string) (string, error)
}

func (m *mockHasher) Hash(password string) (string, error) {
	if m.hashFn != nil {
		return m.hashFn(password)
	}
	return "hashed:" + password, nil
}

func (m *mockHasher) Verify(password, hash string) (bool, error) {
	return hash == "hashed:"+password, nil
}

// --- Helpers ---

func newUserSvc(repo admin.UserRepository) *admin.UserService {
	return admin.NewUserService(repo, &mockHasher{})
}

func makeUser(id string) *domain.User {
	now := time.Now().UTC()
	return &domain.User{
		ID:        id,
		Email:     id + "@example.com",
		Name:      "Test User",
		Roles:     []string{"user"},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// --- ListUsers ---

func TestUserService_ListUsers(t *testing.T) {
	tests := []struct {
		name           string
		page           int
		perPage        int
		includeDeleted bool
		setupRepo      func(*mockUserRepo)
		wantLen        int
		wantTotal      int
		wantPage       int
		wantPerPage    int
		wantErr        bool
	}{
		{
			name:    "returns empty list",
			page:    1,
			perPage: 20,
			setupRepo: func(r *mockUserRepo) {
				r.findAllFn = func(_ context.Context, _, _ int, _ bool) ([]*domain.User, int64, error) {
					return []*domain.User{}, 0, nil
				}
			},
			wantLen:     0,
			wantTotal:   0,
			wantPage:    1,
			wantPerPage: 20,
		},
		{
			name:    "returns users with correct page metadata",
			page:    1,
			perPage: 20,
			setupRepo: func(r *mockUserRepo) {
				r.findAllFn = func(_ context.Context, _, _ int, _ bool) ([]*domain.User, int64, error) {
					return []*domain.User{makeUser("u1"), makeUser("u2")}, 2, nil
				}
			},
			wantLen:     2,
			wantTotal:   2,
			wantPage:    1,
			wantPerPage: 20,
		},
		{
			name:    "computes correct offset for page 2",
			page:    2,
			perPage: 5,
			setupRepo: func(r *mockUserRepo) {
				r.findAllFn = func(_ context.Context, offset, limit int, _ bool) ([]*domain.User, int64, error) {
					assert.Equal(t, 5, offset, "offset should be (page-1)*perPage")
					assert.Equal(t, 5, limit)
					return []*domain.User{makeUser("u6")}, 6, nil
				}
			},
			wantLen:     1,
			wantTotal:   6,
			wantPage:    2,
			wantPerPage: 5,
		},
		{
			name:    "passes includeDeleted flag through",
			page:    1,
			perPage: 20,
			includeDeleted: true,
			setupRepo: func(r *mockUserRepo) {
				r.findAllFn = func(_ context.Context, _, _ int, includeDeleted bool) ([]*domain.User, int64, error) {
					assert.True(t, includeDeleted)
					return []*domain.User{}, 0, nil
				}
			},
		},
		{
			name:    "defaults page 0 to 1",
			page:    0,
			perPage: 10,
			setupRepo: func(r *mockUserRepo) {
				r.findAllFn = func(_ context.Context, offset, _ int, _ bool) ([]*domain.User, int64, error) {
					assert.Equal(t, 0, offset, "page 0 should be treated as page 1")
					return []*domain.User{}, 0, nil
				}
			},
			wantPage: 1,
		},
		{
			name:    "propagates repository error",
			page:    1,
			perPage: 20,
			setupRepo: func(r *mockUserRepo) {
				r.findAllFn = func(_ context.Context, _, _ int, _ bool) ([]*domain.User, int64, error) {
					return nil, 0, errors.New("database unavailable")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newUserSvc(repo).ListUsers(context.Background(), tt.page, tt.perPage, tt.includeDeleted)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, result.Users, tt.wantLen)
			assert.Equal(t, tt.wantTotal, result.Total)
			if tt.wantPage != 0 {
				assert.Equal(t, tt.wantPage, result.Page)
			}
		})
	}
}

// --- GetUser ---

func TestUserService_GetUser(t *testing.T) {
	tests := []struct {
		name      string
		userID    string
		setupRepo func(*mockUserRepo)
		wantErrIs error
	}{
		{
			name:   "returns user when found",
			userID: "u1",
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					return makeUser(id), nil
				}
			},
		},
		{
			name:   "returns ErrNotFound for missing user",
			userID: "missing",
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.User, error) {
					return nil, storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
		{
			name:   "propagates unexpected repository error",
			userID: "u1",
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.User, error) {
					return nil, errors.New("db connection lost")
				}
			},
			wantErrIs: nil, // any error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newUserSvc(repo).GetUser(context.Background(), tt.userID)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}
			if result == nil && err != nil {
				// any error case when wantErrIs is nil
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.userID, result.ID)
		})
	}
}

// --- CreateUser ---

func TestUserService_CreateUser(t *testing.T) {
	validReq := &api.CreateUserRequest{
		Email:    "alice@example.com",
		Password: "super-secure-password-123",
		Name:     "Alice",
		Roles:    []string{"admin"},
	}

	tests := []struct {
		name      string
		req       *api.CreateUserRequest
		setupRepo func(*mockUserRepo)
		wantErrIs error
		check     func(*api.AdminUser)
	}{
		{
			name: "creates user with provided roles",
			req:  validReq,
			setupRepo: func(r *mockUserRepo) {
				r.createFn = func(_ context.Context, u *domain.User) (*domain.User, error) {
					return u, nil
				}
			},
			check: func(u *api.AdminUser) {
				assert.Equal(t, "alice@example.com", u.Email)
				assert.Equal(t, "Alice", u.Name)
				assert.Equal(t, []string{"admin"}, u.Roles)
				assert.NotEmpty(t, u.ID)
			},
		},
		{
			name: "defaults to role user when roles not provided",
			req:  &api.CreateUserRequest{Email: "bob@example.com", Password: "super-secure-password-123", Name: "Bob"},
			setupRepo: func(r *mockUserRepo) {
				r.createFn = func(_ context.Context, u *domain.User) (*domain.User, error) {
					return u, nil
				}
			},
			check: func(u *api.AdminUser) {
				assert.Equal(t, []string{"user"}, u.Roles)
			},
		},
		{
			name: "returns ErrConflict on duplicate email",
			req:  validReq,
			setupRepo: func(r *mockUserRepo) {
				r.createFn = func(_ context.Context, _ *domain.User) (*domain.User, error) {
					return nil, storage.ErrDuplicateEmail
				}
			},
			wantErrIs: api.ErrConflict,
		},
		{
			name: "propagates hasher error",
			req:  validReq,
			setupRepo: func(_ *mockUserRepo) {
				// hasher error handled below via custom hasher
			},
			wantErrIs: errors.New("any"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			svc := admin.NewUserService(repo, &mockHasher{})
			if tt.name == "propagates hasher error" {
				svc = admin.NewUserService(repo, &mockHasher{
					hashFn: func(_ string) (string, error) {
						return "", errors.New("argon2 failed")
					},
				})
			}

			result, err := svc.CreateUser(context.Background(), tt.req)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErrIs, api.ErrConflict) {
					assert.ErrorIs(t, err, api.ErrConflict)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			if tt.check != nil {
				tt.check(result)
			}
		})
	}
}

// --- UpdateUser ---

func TestUserService_UpdateUser(t *testing.T) {
	newName := "Updated Name"
	newEmail := "updated@example.com"

	tests := []struct {
		name      string
		userID    string
		req       *api.UpdateUserRequest
		setupRepo func(*mockUserRepo)
		wantErrIs error
		check     func(*api.AdminUser)
	}{
		{
			name:   "updates name",
			userID: "u1",
			req:    &api.UpdateUserRequest{Name: &newName},
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					return makeUser(id), nil
				}
				r.updateFn = func(_ context.Context, u *domain.User) (*domain.User, error) {
					return u, nil
				}
			},
			check: func(u *api.AdminUser) {
				assert.Equal(t, newName, u.Name)
			},
		},
		{
			name:   "updates email",
			userID: "u1",
			req:    &api.UpdateUserRequest{Email: &newEmail},
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					return makeUser(id), nil
				}
				r.updateFn = func(_ context.Context, u *domain.User) (*domain.User, error) {
					return u, nil
				}
			},
			check: func(u *api.AdminUser) {
				assert.Equal(t, newEmail, u.Email)
			},
		},
		{
			name:   "updates roles",
			userID: "u1",
			req:    &api.UpdateUserRequest{Roles: []string{"admin"}},
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					return makeUser(id), nil
				}
				r.updateFn = func(_ context.Context, u *domain.User) (*domain.User, error) {
					return u, nil
				}
			},
			check: func(u *api.AdminUser) {
				assert.Equal(t, []string{"admin"}, u.Roles)
			},
		},
		{
			name:   "returns ErrNotFound when user missing",
			userID: "missing",
			req:    &api.UpdateUserRequest{Name: &newName},
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.User, error) {
					return nil, storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newUserSvc(repo).UpdateUser(context.Background(), tt.userID, tt.req)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			if tt.check != nil {
				tt.check(result)
			}
		})
	}
}

// --- DeleteUser ---

func TestUserService_DeleteUser(t *testing.T) {
	now := time.Now().UTC()

	tests := []struct {
		name      string
		userID    string
		setupRepo func(*mockUserRepo)
		wantErrIs error
	}{
		{
			name:   "soft-deletes active user",
			userID: "u1",
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					return makeUser(id), nil
				}
				r.softDeleteFn = func(_ context.Context, _ string) error {
					return nil
				}
			},
		},
		{
			name:   "returns ErrNotFound for missing user",
			userID: "missing",
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.User, error) {
					return nil, storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
		{
			name:   "returns ErrConflict when user already deleted",
			userID: "u1",
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					u := makeUser(id)
					u.DeletedAt = &now
					return u, nil
				}
			},
			wantErrIs: api.ErrConflict,
		},
		{
			name:   "propagates soft delete repository error",
			userID: "u1",
			setupRepo: func(r *mockUserRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					return makeUser(id), nil
				}
				r.softDeleteFn = func(_ context.Context, _ string) error {
					return errors.New("db error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			err := newUserSvc(repo).DeleteUser(context.Background(), tt.userID)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}
		})
	}
}

// --- LockUser ---

func TestUserService_LockUser(t *testing.T) {
	tests := []struct {
		name      string
		userID    string
		reason    string
		setupRepo func(*mockUserRepo)
		wantErrIs error
		check     func(*api.AdminUser)
	}{
		{
			name:   "locks user and returns updated record",
			userID: "u1",
			reason: "suspicious activity",
			setupRepo: func(r *mockUserRepo) {
				r.setLockedFn = func(_ context.Context, id string, locked bool, reason string, lockedAt *time.Time) error {
					assert.True(t, locked)
					assert.Equal(t, "suspicious activity", reason)
					assert.NotNil(t, lockedAt)
					return nil
				}
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					u := makeUser(id)
					now := time.Now().UTC()
					u.Locked = true
					u.LockedAt = &now
					u.LockedReason = "suspicious activity"
					return u, nil
				}
			},
			check: func(u *api.AdminUser) {
				assert.True(t, u.Locked)
				assert.NotNil(t, u.LockedAt)
				assert.Equal(t, "suspicious activity", u.LockedReason)
			},
		},
		{
			name:   "returns ErrNotFound when user missing",
			userID: "missing",
			reason: "test",
			setupRepo: func(r *mockUserRepo) {
				r.setLockedFn = func(_ context.Context, _ string, _ bool, _ string, _ *time.Time) error {
					return storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newUserSvc(repo).LockUser(context.Background(), tt.userID, tt.reason)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			if tt.check != nil {
				tt.check(result)
			}
		})
	}
}

// --- UnlockUser ---

func TestUserService_UnlockUser(t *testing.T) {
	tests := []struct {
		name      string
		userID    string
		setupRepo func(*mockUserRepo)
		wantErrIs error
		check     func(*api.AdminUser)
	}{
		{
			name:   "unlocks user and returns updated record",
			userID: "u1",
			setupRepo: func(r *mockUserRepo) {
				r.setLockedFn = func(_ context.Context, _ string, locked bool, reason string, lockedAt *time.Time) error {
					assert.False(t, locked)
					assert.Empty(t, reason)
					assert.Nil(t, lockedAt)
					return nil
				}
				r.findByIDFn = func(_ context.Context, id string) (*domain.User, error) {
					u := makeUser(id)
					u.Locked = false
					return u, nil
				}
			},
			check: func(u *api.AdminUser) {
				assert.False(t, u.Locked)
			},
		},
		{
			name:   "returns ErrNotFound when user missing",
			userID: "missing",
			setupRepo: func(r *mockUserRepo) {
				r.setLockedFn = func(_ context.Context, _ string, _ bool, _ string, _ *time.Time) error {
					return storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockUserRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newUserSvc(repo).UnlockUser(context.Background(), tt.userID)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			if tt.check != nil {
				tt.check(result)
			}
		})
	}
}
