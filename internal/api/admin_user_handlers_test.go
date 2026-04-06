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
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock AdminUserService ---

type mockAdminUserService struct {
	listUsersFn     func(ctx context.Context, page, perPage int, status string) (*api.AdminUserList, error)
	searchUsersFn   func(ctx context.Context, page, perPage int, email, role, status string, createdAfter, createdBefore *time.Time) (*api.AdminUserList, error)
	getUserFn       func(ctx context.Context, userID string) (*api.AdminUser, error)
	createUserFn    func(ctx context.Context, req *api.CreateUserRequest) (*api.AdminUser, error)
	updateUserFn    func(ctx context.Context, userID string, req *api.UpdateUserRequest) (*api.AdminUser, error)
	deleteUserFn    func(ctx context.Context, userID string) error
	lockUserFn      func(ctx context.Context, userID string, reason string) (*api.AdminUser, error)
	unlockUserFn    func(ctx context.Context, userID string) (*api.AdminUser, error)
	bulkLockFn      func(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error)
	bulkUnlockFn    func(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error)
	bulkSuspendFn   func(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error)
	bulkAssignRoleFn func(ctx context.Context, req *api.BulkAssignRoleRequest) (*api.BulkActionResult, error)
	getActivityFn   func(ctx context.Context, userID string, page, perPage int) (*api.UserActivityTimeline, error)
}

func (m *mockAdminUserService) ListUsers(ctx context.Context, page, perPage int, status string) (*api.AdminUserList, error) {
	if m.listUsersFn != nil {
		return m.listUsersFn(ctx, page, perPage, status)
	}
	return &api.AdminUserList{
		Users:   []api.AdminUser{{ID: "u1", Email: "a@b.com", Name: "Alice", Roles: []string{"user"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminUserService) SearchUsers(ctx context.Context, page, perPage int, email, role, status string, createdAfter, createdBefore *time.Time) (*api.AdminUserList, error) {
	if m.searchUsersFn != nil {
		return m.searchUsersFn(ctx, page, perPage, email, role, status, createdAfter, createdBefore)
	}
	return &api.AdminUserList{
		Users:   []api.AdminUser{{ID: "u1", Email: "a@b.com", Name: "Alice", Roles: []string{"user"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminUserService) BulkLock(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
	if m.bulkLockFn != nil {
		return m.bulkLockFn(ctx, req)
	}
	return &api.BulkActionResult{Affected: int64(len(req.UserIDs))}, nil
}

func (m *mockAdminUserService) BulkUnlock(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
	if m.bulkUnlockFn != nil {
		return m.bulkUnlockFn(ctx, req)
	}
	return &api.BulkActionResult{Affected: int64(len(req.UserIDs))}, nil
}

func (m *mockAdminUserService) BulkSuspend(ctx context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
	if m.bulkSuspendFn != nil {
		return m.bulkSuspendFn(ctx, req)
	}
	return &api.BulkActionResult{Affected: int64(len(req.UserIDs))}, nil
}

func (m *mockAdminUserService) BulkAssignRole(ctx context.Context, req *api.BulkAssignRoleRequest) (*api.BulkActionResult, error) {
	if m.bulkAssignRoleFn != nil {
		return m.bulkAssignRoleFn(ctx, req)
	}
	return &api.BulkActionResult{Affected: int64(len(req.UserIDs))}, nil
}

func (m *mockAdminUserService) GetActivity(ctx context.Context, userID string, page, perPage int) (*api.UserActivityTimeline, error) {
	if m.getActivityFn != nil {
		return m.getActivityFn(ctx, userID, page, perPage)
	}
	return &api.UserActivityTimeline{
		Events:  []api.UserActivityEntry{},
		Total:   0,
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
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
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
		listUsersFn: func(_ context.Context, page, perPage int, status string) (*api.AdminUserList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.Equal(t, "deleted", status)
			return &api.AdminUserList{Users: []api.AdminUser{}, Total: 25, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users?page=2&per_page=10&status=deleted", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUserList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
	assert.Equal(t, 25, resp.Total)
}

func TestAdminListUsers_ServiceError(t *testing.T) {
	svc := &mockAdminUserService{
		listUsersFn: func(_ context.Context, _, _ int, _ string) (*api.AdminUserList, error) {
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

// --- Update User Validation ---

func TestAdminUpdateUser_InvalidJSON(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPatch, "/admin/users/user-42", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Lock User InvalidJSON ---

func TestAdminLockUser_InvalidJSON(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPost, "/admin/users/user-42/lock", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- List Users with negative page ---

func TestAdminListUsers_NegativePage(t *testing.T) {
	svc := &mockAdminUserService{
		listUsersFn: func(_ context.Context, page, perPage int, _ string) (*api.AdminUserList, error) {
			assert.Equal(t, 1, page) // Clamped to 1
			return &api.AdminUserList{Users: []api.AdminUser{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users?page=-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Advanced Search (List with filters) ---

func TestAdminListUsers_WithEmailFilter(t *testing.T) {
	svc := &mockAdminUserService{
		searchUsersFn: func(_ context.Context, page, perPage int, email, role, status string, createdAfter, createdBefore *time.Time) (*api.AdminUserList, error) {
			assert.Equal(t, "alice", email)
			assert.Equal(t, "", role)
			assert.Equal(t, "", status)
			assert.Nil(t, createdAfter)
			assert.Nil(t, createdBefore)
			return &api.AdminUserList{Users: []api.AdminUser{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users?email=alice", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListUsers_WithRoleFilter(t *testing.T) {
	svc := &mockAdminUserService{
		searchUsersFn: func(_ context.Context, _, _ int, _, role, _ string, _, _ *time.Time) (*api.AdminUserList, error) {
			assert.Equal(t, "admin", role)
			return &api.AdminUserList{Users: []api.AdminUser{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users?role=admin", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListUsers_WithDateRange(t *testing.T) {
	svc := &mockAdminUserService{
		searchUsersFn: func(_ context.Context, _, _ int, _, _, _ string, after, before *time.Time) (*api.AdminUserList, error) {
			require.NotNil(t, after)
			require.NotNil(t, before)
			assert.Equal(t, 2026, after.Year())
			assert.Equal(t, 2026, before.Year())
			return &api.AdminUserList{Users: []api.AdminUser{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users?created_after=2026-01-01T00:00:00Z&created_before=2026-12-31T23:59:59Z", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListUsers_InvalidCreatedAfter(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodGet, "/admin/users?created_after=not-a-date", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminListUsers_InvalidCreatedBefore(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodGet, "/admin/users?created_before=not-a-date", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminListUsers_AllFilters(t *testing.T) {
	svc := &mockAdminUserService{
		searchUsersFn: func(_ context.Context, _, _ int, email, role, status string, after, before *time.Time) (*api.AdminUserList, error) {
			assert.Equal(t, "bob", email)
			assert.Equal(t, "user", role)
			assert.Equal(t, "locked", status)
			assert.NotNil(t, after)
			return &api.AdminUserList{Users: []api.AdminUser{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users?email=bob&role=user&status=locked&created_after=2026-01-01T00:00:00Z", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Bulk Lock ---

func TestAdminBulkLock_Success(t *testing.T) {
	svc := &mockAdminUserService{
		bulkLockFn: func(_ context.Context, req *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
			assert.Len(t, req.UserIDs, 2)
			assert.Equal(t, "policy violation", req.Reason)
			return &api.BulkActionResult{Affected: 2}, nil
		},
	}
	r := newAdminUserRouter(svc)
	body := map[string]interface{}{
		"user_ids": []string{"u1", "u2"},
		"reason":   "policy violation",
	}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/lock", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp api.BulkActionResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(2), resp.Affected)
}

func TestAdminBulkLock_EmptyUserIDs(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]interface{}{"user_ids": []string{}}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/lock", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminBulkLock_InvalidJSON(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/lock", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminBulkLock_ServiceError(t *testing.T) {
	svc := &mockAdminUserService{
		bulkLockFn: func(_ context.Context, _ *api.BulkUserActionRequest) (*api.BulkActionResult, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminUserRouter(svc)
	body := map[string]interface{}{"user_ids": []string{"u1"}}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/lock", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Bulk Unlock ---

func TestAdminBulkUnlock_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]interface{}{"user_ids": []string{"u1", "u2"}}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/unlock", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp api.BulkActionResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(2), resp.Affected)
}

func TestAdminBulkUnlock_InvalidJSON(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/unlock", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Bulk Suspend ---

func TestAdminBulkSuspend_Success(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]interface{}{
		"user_ids": []string{"u1", "u2", "u3"},
		"reason":   "account review",
	}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/suspend", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp api.BulkActionResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(3), resp.Affected)
}

func TestAdminBulkSuspend_InvalidJSON(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/suspend", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Bulk Assign Role ---

func TestAdminBulkAssignRole_Success(t *testing.T) {
	svc := &mockAdminUserService{
		bulkAssignRoleFn: func(_ context.Context, req *api.BulkAssignRoleRequest) (*api.BulkActionResult, error) {
			assert.Equal(t, "admin", req.Role)
			assert.Len(t, req.UserIDs, 2)
			return &api.BulkActionResult{Affected: 2}, nil
		},
	}
	r := newAdminUserRouter(svc)
	body := map[string]interface{}{
		"user_ids": []string{"u1", "u2"},
		"role":     "admin",
	}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/assign-role", body)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp api.BulkActionResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(2), resp.Affected)
}

func TestAdminBulkAssignRole_MissingRole(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]interface{}{"user_ids": []string{"u1"}}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/assign-role", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminBulkAssignRole_InvalidRole(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	body := map[string]interface{}{
		"user_ids": []string{"u1"},
		"role":     "superadmin",
	}
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/assign-role", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminBulkAssignRole_InvalidJSON(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodPost, "/admin/users/bulk/assign-role", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Activity Timeline ---

func TestAdminActivity_Success(t *testing.T) {
	now := time.Now()
	svc := &mockAdminUserService{
		getActivityFn: func(_ context.Context, userID string, page, perPage int) (*api.UserActivityTimeline, error) {
			assert.Equal(t, "user-42", userID)
			assert.Equal(t, 1, page)
			assert.Equal(t, 20, perPage)
			return &api.UserActivityTimeline{
				Events: []api.UserActivityEntry{
					{ID: "a1", EventType: "admin_user_create", CreatedAt: now},
				},
				Total:   1,
				Page:    1,
				PerPage: 20,
			}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/activity", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp api.UserActivityTimeline
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Events, 1)
	assert.Equal(t, "admin_user_create", resp.Events[0].EventType)
}

func TestAdminActivity_WithPagination(t *testing.T) {
	svc := &mockAdminUserService{
		getActivityFn: func(_ context.Context, _ string, page, perPage int) (*api.UserActivityTimeline, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			return &api.UserActivityTimeline{Events: []api.UserActivityEntry{}, Total: 25, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/activity?page=2&per_page=10", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminActivity_NotFound(t *testing.T) {
	svc := &mockAdminUserService{
		getActivityFn: func(_ context.Context, _ string, _, _ int) (*api.UserActivityTimeline, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/nonexistent/activity", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminActivity_ServiceError(t *testing.T) {
	svc := &mockAdminUserService{
		getActivityFn: func(_ context.Context, _ string, _, _ int) (*api.UserActivityTimeline, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminUserRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/activity", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Admin Health ---

func TestAdminHealth(t *testing.T) {
	r := newAdminUserRouter(&mockAdminUserService{})
	w := doRequest(r, http.MethodGet, "/health", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "healthy", resp["status"])
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
