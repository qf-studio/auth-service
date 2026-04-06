package gdpr_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/gdpr"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

// testNow is a fixed timestamp for deterministic tests.
var testNow = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)

func newTestService(
	consentRepo *mocks.MockGDPRConsentRepository,
	deletionRepo *mocks.MockGDPRDeletionRepository,
	exportRepo *mocks.MockGDPRExportRepository,
) *gdpr.Service {
	svc := gdpr.NewService(consentRepo, deletionRepo, exportRepo)
	svc.SetNowFunc(func() time.Time { return testNow })
	return svc
}

// --- Consent Tracking Tests ---

func TestGrantConsent_Success(t *testing.T) {
	consentRepo := &mocks.MockGDPRConsentRepository{
		CreateFn: func(_ context.Context, record *domain.ConsentRecord) (*domain.ConsentRecord, error) {
			assert.Equal(t, "user-1", record.UserID)
			assert.Equal(t, domain.ConsentTypeMarketing, record.ConsentType)
			assert.True(t, record.Granted)
			assert.Equal(t, "192.168.1.1", record.IPAddress)
			assert.Equal(t, "TestAgent", record.UserAgent)
			assert.NotEmpty(t, record.ID)
			return record, nil
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	rec, err := svc.GrantConsent(context.Background(), "user-1", domain.ConsentTypeMarketing, "192.168.1.1", "TestAgent")
	require.NoError(t, err)
	assert.Equal(t, "user-1", rec.UserID)
	assert.True(t, rec.Granted)
}

func TestGrantConsent_DuplicateError(t *testing.T) {
	consentRepo := &mocks.MockGDPRConsentRepository{
		CreateFn: func(_ context.Context, _ *domain.ConsentRecord) (*domain.ConsentRecord, error) {
			return nil, storage.ErrDuplicateConsent
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	_, err := svc.GrantConsent(context.Background(), "user-1", domain.ConsentTypeMarketing, "192.168.1.1", "TestAgent")
	assert.ErrorIs(t, err, storage.ErrDuplicateConsent)
}

func TestRevokeConsent_Success(t *testing.T) {
	consentRepo := &mocks.MockGDPRConsentRepository{
		RevokeFn: func(_ context.Context, id string, revokedAt time.Time) error {
			assert.Equal(t, "consent-1", id)
			assert.Equal(t, testNow, revokedAt)
			return nil
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	err := svc.RevokeConsent(context.Background(), "consent-1")
	require.NoError(t, err)
}

func TestRevokeConsent_NotFound(t *testing.T) {
	consentRepo := &mocks.MockGDPRConsentRepository{
		RevokeFn: func(_ context.Context, _ string, _ time.Time) error {
			return storage.ErrNotFound
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	err := svc.RevokeConsent(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestGetUserConsents_Success(t *testing.T) {
	now := testNow
	records := []domain.ConsentRecord{
		{ID: "c1", UserID: "user-1", ConsentType: domain.ConsentTypeMarketing, Granted: true, GrantedAt: &now},
		{ID: "c2", UserID: "user-1", ConsentType: domain.ConsentTypeAnalytics, Granted: false, RevokedAt: &now},
	}

	consentRepo := &mocks.MockGDPRConsentRepository{
		FindByUserIDFn: func(_ context.Context, userID string) ([]domain.ConsentRecord, error) {
			assert.Equal(t, "user-1", userID)
			return records, nil
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	result, err := svc.GetUserConsents(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestGetUserConsents_Empty(t *testing.T) {
	consentRepo := &mocks.MockGDPRConsentRepository{
		FindByUserIDFn: func(_ context.Context, _ string) ([]domain.ConsentRecord, error) {
			return nil, nil
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	result, err := svc.GetUserConsents(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestGetConsentByType_Success(t *testing.T) {
	now := testNow
	record := &domain.ConsentRecord{
		ID: "c1", UserID: "user-1", ConsentType: domain.ConsentTypeMarketing, Granted: true, GrantedAt: &now,
	}

	consentRepo := &mocks.MockGDPRConsentRepository{
		FindByUserIDAndTypeFn: func(_ context.Context, userID, consentType string) (*domain.ConsentRecord, error) {
			assert.Equal(t, "user-1", userID)
			assert.Equal(t, domain.ConsentTypeMarketing, consentType)
			return record, nil
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	result, err := svc.GetConsentByType(context.Background(), "user-1", domain.ConsentTypeMarketing)
	require.NoError(t, err)
	assert.Equal(t, "c1", result.ID)
}

func TestGetConsentByType_NotFound(t *testing.T) {
	consentRepo := &mocks.MockGDPRConsentRepository{
		FindByUserIDAndTypeFn: func(_ context.Context, _ string, _ string) (*domain.ConsentRecord, error) {
			return nil, storage.ErrNotFound
		},
	}

	svc := newTestService(consentRepo, &mocks.MockGDPRDeletionRepository{}, &mocks.MockGDPRExportRepository{})

	_, err := svc.GetConsentByType(context.Background(), "user-1", domain.ConsentTypeMarketing)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// --- Data Export Tests ---

func TestExportUserData_Success(t *testing.T) {
	user := &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: "secret-hash",
		Name:         "Test User",
		CreatedAt:    testNow,
		UpdatedAt:    testNow,
	}
	oauthAccounts := []domain.OAuthAccount{
		{ID: "oa1", UserID: "user-1", Provider: "google", ProviderUserID: "g123"},
	}
	refreshTokens := []domain.RefreshTokenRecord{
		{Signature: "sig1", UserID: "user-1", ExpiresAt: testNow.Add(24 * time.Hour)},
	}
	consentRecords := []domain.ConsentRecord{
		{ID: "c1", UserID: "user-1", ConsentType: domain.ConsentTypeMarketing, Granted: true},
	}

	exportRepo := &mocks.MockGDPRExportRepository{
		GetUserDataFn: func(_ context.Context, _ string) (*domain.User, error) {
			return user, nil
		},
		GetOAuthAccountsFn: func(_ context.Context, _ string) ([]domain.OAuthAccount, error) {
			return oauthAccounts, nil
		},
		GetRefreshTokensFn: func(_ context.Context, _ string) ([]domain.RefreshTokenRecord, error) {
			return refreshTokens, nil
		},
		GetConsentRecordsFn: func(_ context.Context, _ string) ([]domain.ConsentRecord, error) {
			return consentRecords, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, &mocks.MockGDPRDeletionRepository{}, exportRepo)

	data, err := svc.ExportUserData(context.Background(), "user-1")
	require.NoError(t, err)

	var export domain.UserDataExport
	require.NoError(t, json.Unmarshal(data, &export))

	assert.Equal(t, "user-1", export.User.ID)
	assert.Equal(t, "[REDACTED]", export.User.PasswordHash)
	assert.Len(t, export.OAuthAccounts, 1)
	assert.Len(t, export.RefreshTokens, 1)
	assert.Len(t, export.ConsentRecords, 1)
	assert.Equal(t, testNow, export.ExportedAt)
}

func TestExportUserData_UserNotFound(t *testing.T) {
	exportRepo := &mocks.MockGDPRExportRepository{
		GetUserDataFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, &mocks.MockGDPRDeletionRepository{}, exportRepo)

	_, err := svc.ExportUserData(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestExportUserData_OAuthError(t *testing.T) {
	exportRepo := &mocks.MockGDPRExportRepository{
		GetUserDataFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: "user-1"}, nil
		},
		GetOAuthAccountsFn: func(_ context.Context, _ string) ([]domain.OAuthAccount, error) {
			return nil, errors.New("db connection failed")
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, &mocks.MockGDPRDeletionRepository{}, exportRepo)

	_, err := svc.ExportUserData(context.Background(), "user-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "export oauth accounts")
}

// --- Account Deletion Tests ---

func TestRequestDeletion_Success(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindPendingByUserIDFn: func(_ context.Context, _ string) (*domain.DeletionRequest, error) {
			return nil, storage.ErrNotFound
		},
		CreateFn: func(_ context.Context, req *domain.DeletionRequest) (*domain.DeletionRequest, error) {
			assert.Equal(t, "user-1", req.UserID)
			assert.Equal(t, domain.DeletionStatusPending, req.Status)
			assert.Equal(t, "privacy concerns", req.Reason)
			expectedSchedule := testNow.AddDate(0, 0, domain.DeletionGracePeriodDays)
			assert.Equal(t, expectedSchedule, req.ScheduledAt)
			return req, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	req, err := svc.RequestDeletion(context.Background(), "user-1", "privacy concerns")
	require.NoError(t, err)
	assert.Equal(t, "user-1", req.UserID)
	assert.Equal(t, domain.DeletionStatusPending, req.Status)
}

func TestRequestDeletion_AlreadyRequested(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindPendingByUserIDFn: func(_ context.Context, _ string) (*domain.DeletionRequest, error) {
			return &domain.DeletionRequest{ID: "existing", Status: domain.DeletionStatusPending}, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	_, err := svc.RequestDeletion(context.Background(), "user-1", "privacy concerns")
	assert.ErrorIs(t, err, domain.ErrDeletionAlreadyRequested)
}

func TestCancelDeletion_Success(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindByIDFn: func(_ context.Context, id string) (*domain.DeletionRequest, error) {
			return &domain.DeletionRequest{ID: id, Status: domain.DeletionStatusPending}, nil
		},
		CancelFn: func(_ context.Context, id, cancelledBy string, cancelledAt time.Time) error {
			assert.Equal(t, "req-1", id)
			assert.Equal(t, "admin-1", cancelledBy)
			assert.Equal(t, testNow, cancelledAt)
			return nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	err := svc.CancelDeletion(context.Background(), "req-1", "admin-1")
	require.NoError(t, err)
}

func TestCancelDeletion_AlreadyCompleted(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindByIDFn: func(_ context.Context, _ string) (*domain.DeletionRequest, error) {
			return &domain.DeletionRequest{Status: domain.DeletionStatusCompleted}, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	err := svc.CancelDeletion(context.Background(), "req-1", "admin-1")
	assert.ErrorIs(t, err, domain.ErrDeletionAlreadyCompleted)
}

func TestCancelDeletion_AlreadyCancelled(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindByIDFn: func(_ context.Context, _ string) (*domain.DeletionRequest, error) {
			return &domain.DeletionRequest{Status: domain.DeletionStatusCancelled}, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	err := svc.CancelDeletion(context.Background(), "req-1", "admin-1")
	assert.ErrorIs(t, err, domain.ErrDeletionNotCancellable)
}

func TestCancelDeletion_NotFound(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindByIDFn: func(_ context.Context, _ string) (*domain.DeletionRequest, error) {
			return nil, storage.ErrNotFound
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	err := svc.CancelDeletion(context.Background(), "nonexistent", "admin-1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestGetDeletionRequest_Success(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindByUserIDFn: func(_ context.Context, userID string) (*domain.DeletionRequest, error) {
			return &domain.DeletionRequest{ID: "req-1", UserID: userID, Status: domain.DeletionStatusPending}, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	req, err := svc.GetDeletionRequest(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Equal(t, "req-1", req.ID)
}

func TestExecutePendingDeletions_Success(t *testing.T) {
	deletionCalls := make(map[string]bool)

	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindDueForExecutionFn: func(_ context.Context, _ time.Time) ([]domain.DeletionRequest, error) {
			return []domain.DeletionRequest{
				{ID: "req-1", UserID: "user-1", Status: domain.DeletionStatusApproved},
				{ID: "req-2", UserID: "user-2", Status: domain.DeletionStatusApproved},
			}, nil
		},
		UpdateStatusFn: func(_ context.Context, id, status string, _ time.Time) error {
			assert.Equal(t, domain.DeletionStatusCompleted, status)
			deletionCalls[id] = true
			return nil
		},
	}

	consentRepo := &mocks.MockGDPRConsentRepository{
		DeleteByUserIDFn: func(_ context.Context, _ string) error { return nil },
	}

	exportRepo := &mocks.MockGDPRExportRepository{
		DeleteRefreshTokensFn: func(_ context.Context, _ string) error { return nil },
		DeleteOAuthAccountsFn: func(_ context.Context, _ string) error { return nil },
		AnonymizeAuditLogsFn:  func(_ context.Context, _ string) error { return nil },
		SoftDeleteUserFn:      func(_ context.Context, _ string) error { return nil },
	}

	svc := newTestService(consentRepo, deletionRepo, exportRepo)

	count, err := svc.ExecutePendingDeletions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.True(t, deletionCalls["req-1"])
	assert.True(t, deletionCalls["req-2"])
}

func TestExecutePendingDeletions_NoDueRequests(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindDueForExecutionFn: func(_ context.Context, _ time.Time) ([]domain.DeletionRequest, error) {
			return nil, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	count, err := svc.ExecutePendingDeletions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestExecutePendingDeletions_PartialFailure(t *testing.T) {
	callCount := 0
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		FindDueForExecutionFn: func(_ context.Context, _ time.Time) ([]domain.DeletionRequest, error) {
			return []domain.DeletionRequest{
				{ID: "req-1", UserID: "user-1", Status: domain.DeletionStatusApproved},
				{ID: "req-2", UserID: "user-2", Status: domain.DeletionStatusApproved},
			}, nil
		},
		UpdateStatusFn: func(_ context.Context, _ string, _ string, _ time.Time) error {
			return nil
		},
	}

	consentRepo := &mocks.MockGDPRConsentRepository{
		DeleteByUserIDFn: func(_ context.Context, _ string) error { return nil },
	}

	exportRepo := &mocks.MockGDPRExportRepository{
		DeleteRefreshTokensFn: func(_ context.Context, userID string) error {
			callCount++
			if callCount == 2 {
				return errors.New("db connection lost")
			}
			return nil
		},
		DeleteOAuthAccountsFn: func(_ context.Context, _ string) error { return nil },
		AnonymizeAuditLogsFn:  func(_ context.Context, _ string) error { return nil },
		SoftDeleteUserFn:      func(_ context.Context, _ string) error { return nil },
	}

	svc := newTestService(consentRepo, deletionRepo, exportRepo)

	count, err := svc.ExecutePendingDeletions(context.Background())
	assert.Error(t, err)
	assert.Equal(t, 1, count) // First succeeded, second failed.
}

func TestApprovePendingDeletion_Success(t *testing.T) {
	deletionRepo := &mocks.MockGDPRDeletionRepository{
		UpdateStatusFn: func(_ context.Context, id, status string, _ time.Time) error {
			assert.Equal(t, "req-1", id)
			assert.Equal(t, domain.DeletionStatusApproved, status)
			return nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, deletionRepo, &mocks.MockGDPRExportRepository{})

	err := svc.ApprovePendingDeletion(context.Background(), "req-1")
	require.NoError(t, err)
}

// --- Data Retention Tests ---

func TestCleanupExpiredData_Success(t *testing.T) {
	exportRepo := &mocks.MockGDPRExportRepository{
		DeleteExpiredSoftDeletedUsersFn: func(_ context.Context, days int) (int64, error) {
			assert.Equal(t, 90, days)
			return 5, nil
		},
		DeleteExpiredRefreshTokensFn: func(_ context.Context, days int) (int64, error) {
			assert.Equal(t, 30, days)
			return 100, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, &mocks.MockGDPRDeletionRepository{}, exportRepo)

	result, err := svc.CleanupExpiredData(context.Background(), gdpr.DefaultRetentionConfig())
	require.NoError(t, err)
	assert.Equal(t, int64(5), result.UsersDeleted)
	assert.Equal(t, int64(100), result.TokensDeleted)
}

func TestCleanupExpiredData_CustomConfig(t *testing.T) {
	exportRepo := &mocks.MockGDPRExportRepository{
		DeleteExpiredSoftDeletedUsersFn: func(_ context.Context, days int) (int64, error) {
			assert.Equal(t, 180, days)
			return 2, nil
		},
		DeleteExpiredRefreshTokensFn: func(_ context.Context, days int) (int64, error) {
			assert.Equal(t, 7, days)
			return 50, nil
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, &mocks.MockGDPRDeletionRepository{}, exportRepo)

	config := gdpr.RetentionConfig{
		SoftDeletedUserRetentionDays: 180,
		ExpiredTokenRetentionDays:    7,
	}
	result, err := svc.CleanupExpiredData(context.Background(), config)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.UsersDeleted)
	assert.Equal(t, int64(50), result.TokensDeleted)
}

func TestCleanupExpiredData_UserDeletionError(t *testing.T) {
	exportRepo := &mocks.MockGDPRExportRepository{
		DeleteExpiredSoftDeletedUsersFn: func(_ context.Context, _ int) (int64, error) {
			return 0, errors.New("permission denied")
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, &mocks.MockGDPRDeletionRepository{}, exportRepo)

	_, err := svc.CleanupExpiredData(context.Background(), gdpr.DefaultRetentionConfig())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cleanup expired users")
}

func TestCleanupExpiredData_TokenDeletionError(t *testing.T) {
	exportRepo := &mocks.MockGDPRExportRepository{
		DeleteExpiredSoftDeletedUsersFn: func(_ context.Context, _ int) (int64, error) {
			return 3, nil
		},
		DeleteExpiredRefreshTokensFn: func(_ context.Context, _ int) (int64, error) {
			return 0, errors.New("timeout")
		},
	}

	svc := newTestService(&mocks.MockGDPRConsentRepository{}, &mocks.MockGDPRDeletionRepository{}, exportRepo)

	_, err := svc.CleanupExpiredData(context.Background(), gdpr.DefaultRetentionConfig())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cleanup expired tokens")
}

func TestDefaultRetentionConfig(t *testing.T) {
	config := gdpr.DefaultRetentionConfig()
	assert.Equal(t, 90, config.SoftDeletedUserRetentionDays)
	assert.Equal(t, 30, config.ExpiredTokenRetentionDays)
}
