package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
)

// --- Mock AdminUserService ---

type mockAdminUserService struct {
	listUsersFn  func(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminUserList, error)
	getUserFn    func(ctx context.Context, userID string) (*api.AdminUser, error)
	createUserFn func(ctx context.Context, req *api.CreateUserRequest) (*api.AdminUser, error)
	updateUserFn func(ctx context.Context, userID string, req *api.UpdateUserRequest) (*api.AdminUser, error)
	deleteUserFn func(ctx context.Context, userID string) error
	lockUserFn   func(ctx context.Context, userID string, reason string) (*api.AdminUser, error)
	unlockUserFn func(ctx context.Context, userID string) (*api.AdminUser, error)
}

func (m *mockAdminUserService) ListUsers(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminUserList, error) {
	if m.listUsersFn != nil {
		return m.listUsersFn(ctx, page, perPage, includeDeleted)
	}
	return &api.AdminUserList{
		Users:   []api.AdminUser{{ID: "u1", Email: "a@b.com", Name: "Alice", Roles: []string{"user"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminUserService) GetUser(ctx context.Context, userID string) (*api.AdminUser, error) {
	if m.getUserFn != nil {
		return m.getUserFn(ctx, userID)
	}
	return &api.AdminUser{ID: userID, Email: "a@b.com", Name: "Alice", Roles: []string{"user"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminUserService) CreateUser(ctx context.Context, req *api.CreateUserRequest) (*api.AdminUser, error) {
	if m.createUserFn != nil {
		return m.createUserFn(ctx, req)
	}
	return &api.AdminUser{ID: "new-user", Email: req.Email, Name: req.Name, Roles: req.Roles, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminUserService) UpdateUser(ctx context.Context, userID string, req *api.UpdateUserRequest) (*api.AdminUser, error) {
	if m.updateUserFn != nil {
		return m.updateUserFn(ctx, userID, req)
	}
	name := "Alice"
	if req.Name != nil {
		name = *req.Name
	}
	return &api.AdminUser{ID: userID, Email: "a@b.com", Name: name, Roles: []string{"user"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminUserService) DeleteUser(ctx context.Context, userID string) error {
	if m.deleteUserFn != nil {
		return m.deleteUserFn(ctx, userID)
	}
	return nil
}

func (m *mockAdminUserService) LockUser(ctx context.Context, userID string, reason string) (*api.AdminUser, error) {
	if m.lockUserFn != nil {
		return m.lockUserFn(ctx, userID, reason)
	}
	now := time.Now()
	return &api.AdminUser{ID: userID, Email: "a@b.com", Name: "Alice", Roles: []string{"user"}, Locked: true, LockedAt: &now, LockedReason: reason, CreatedAt: now, UpdatedAt: now}, nil
}

func (m *mockAdminUserService) UnlockUser(ctx context.Context, userID string) (*api.AdminUser, error) {
	if m.unlockUserFn != nil {
		return m.unlockUserFn(ctx, userID)
	}
	now := time.Now()
	return &api.AdminUser{ID: userID, Email: "a@b.com", Name: "Alice", Roles: []string{"user"}, Locked: false, CreatedAt: now, UpdatedAt: now}, nil
}

// --- Helper ---

func newAdminUserRouter(userSvc api.AdminUserService) *gin.Engine {
	svc := &api.AdminServices{Users: userSvc}
	return api.NewAdminRouter(svc)
}

// --- List Users ---

func TestAdminListUsers_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodGet, "/admin/users", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUserList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Users, 1)
	assert.Equal(t, 1, resp.Page)
	assert.Equal(t, 20, resp.PerPage)
}

func TestAdminListUsers_Pagination(t *testing.T) {
	svc := &mockAdminUserService{
		listUsersFn: func(_ context.Context, page, perPage int, includeDeleted bool) (*api.AdminUserList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.True(t, includeDeleted)
			return &api.AdminUserList{Users: []api.AdminUser{}, Total: 25, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users?page=2&per_page=10&include_deleted=true", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUserList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
	assert.Equal(t, 25, resp.Total)
}

func TestAdminListUsers_ServiceError(t *testing.T) {
	svc := &mockAdminUserService{
		listUsersFn: func(_ context.Context, _, _ int, _ bool) (*api.AdminUserList, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Get User ---

func TestAdminGetUser_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodGet, "/admin/users/user-42", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user-42", resp.ID)
}

func TestAdminGetUser_NotFound(t *testing.T) {
	svc := &mockAdminUserService{
		getUserFn: func(_ context.Context, _ string) (*api.AdminUser, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create User ---

func TestAdminCreateUser_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]interface{}{
		"email":    "new@example.com",
		"password": "super-secure-password-123",
		"name":     "New User",
		"roles":    []string{"user"},
	}
	w := doRequest(r, http.MethodPost, "/admin/users", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "new@example.com", resp.Email)
	assert.Equal(t, "New User", resp.Name)
}

func TestAdminCreateUser_ValidationError(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	// Missing required fields
	body := map[string]string{"email": "bad"}
	w := doRequest(r, http.MethodPost, "/admin/users", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateUser_InvalidJSON(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPost, "/admin/users", nil)

	// nil body → ShouldBindJSON fails with EOF
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateUser_Conflict(t *testing.T) {
	svc := &mockAdminUserService{
		createUserFn: func(_ context.Context, _ *api.CreateUserRequest) (*api.AdminUser, error) {
			return nil, fmt.Errorf("email already exists: %w", api.ErrConflict)
		},
	}
	r := newAdminUserRouter(svc)
	body := map[string]interface{}{
		"email":    "dup@example.com",
		"password": "super-secure-password-123",
		"name":     "Dup User",
	}
	w := doRequest(r, http.MethodPost, "/admin/users", body)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Update User ---

func TestAdminUpdateUser_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	name := "Updated Name"
	body := map[string]interface{}{"name": name}
	w := doRequest(r, http.MethodPatch, "/admin/users/user-42", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Updated Name", resp.Name)
}

func TestAdminUpdateUser_NotFound(t *testing.T) {
	svc := &mockAdminUserService{
		updateUserFn: func(_ context.Context, _ string, _ *api.UpdateUserRequest) (*api.AdminUser, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminUserRouter(svc)
	body := map[string]interface{}{"name": "Nope"}
	w := doRequest(r, http.MethodPatch, "/admin/users/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Delete User (soft-delete) ---

func TestAdminDeleteUser_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodDelete, "/admin/users/user-42", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteUser_NotFound(t *testing.T) {
	svc := &mockAdminUserService{
		deleteUserFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/users/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminDeleteUser_AlreadyDeleted(t *testing.T) {
	svc := &mockAdminUserService{
		deleteUserFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("user already deleted: %w", api.ErrConflict)
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/users/deleted-user", nil)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Lock User ---

func TestAdminLockUser_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]string{"reason": "Suspicious activity detected"}
	w := doRequest(r, http.MethodPost, "/admin/users/user-42/lock", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Locked)
	assert.NotNil(t, resp.LockedAt)
	assert.Equal(t, "Suspicious activity detected", resp.LockedReason)
}

func TestAdminLockUser_MissingReason(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]string{}
	w := doRequest(r, http.MethodPost, "/admin/users/user-42/lock", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminLockUser_NotFound(t *testing.T) {
	svc := &mockAdminUserService{
		lockUserFn: func(_ context.Context, _ string, _ string) (*api.AdminUser, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminUserRouter(svc)
	body := map[string]string{"reason": "test"}
	w := doRequest(r, http.MethodPost, "/admin/users/nonexistent/lock", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Unlock User ---

func TestAdminUnlockUser_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPost, "/admin/users/user-42/unlock", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUser
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Locked)
}

func TestAdminUnlockUser_NotFound(t *testing.T) {
	svc := &mockAdminUserService{
		unlockUserFn: func(_ context.Context, _ string) (*api.AdminUser, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodPost, "/admin/users/nonexistent/unlock", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Admin Health ---

func TestAdminHealth(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodGet, "/health", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp["status"])
}

// --- Correlation ID ---

func TestAdminCorrelationID(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})

	// Without X-Request-ID → generates one.
	w := doRequest(r, http.MethodGet, "/health", nil)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))

	// With X-Request-ID → preserves it.
	w = doRequest(r, http.MethodGet, "/health", nil, "X-Request-ID", "custom-id-123")
	assert.Equal(t, "custom-id-123", w.Header().Get("X-Request-ID"))
}
