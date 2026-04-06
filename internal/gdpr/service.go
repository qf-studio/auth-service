package gdpr

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Service handles GDPR-related business logic: data export, account deletion,
// consent tracking, and data retention.
type Service struct {
	consentRepo  storage.GDPRConsentRepository
	deletionRepo storage.GDPRDeletionRepository
	exportRepo   storage.GDPRExportRepository
	nowFunc      func() time.Time
}

// NewService creates a new GDPR service.
func NewService(
	consentRepo storage.GDPRConsentRepository,
	deletionRepo storage.GDPRDeletionRepository,
	exportRepo storage.GDPRExportRepository,
) *Service {
	return &Service{
		consentRepo:  consentRepo,
		deletionRepo: deletionRepo,
		exportRepo:   exportRepo,
		nowFunc:      func() time.Time { return time.Now().UTC() },
	}
}

// SetNowFunc overrides the time source (used in tests for deterministic timestamps).
func (s *Service) SetNowFunc(fn func() time.Time) {
	s.nowFunc = fn
}

// --- Consent Tracking ---

// GrantConsent records a user's consent for a specific type.
func (s *Service) GrantConsent(ctx context.Context, userID, consentType, ipAddress, userAgent string) (*domain.ConsentRecord, error) {
	now := s.nowFunc()
	record := &domain.ConsentRecord{
		ID:          uuid.New().String(),
		UserID:      userID,
		ConsentType: consentType,
		Granted:     true,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		GrantedAt:   &now,
		CreatedAt:   now,
	}

	created, err := s.consentRepo.Create(ctx, record)
	if err != nil {
		return nil, fmt.Errorf("grant consent: %w", err)
	}
	return created, nil
}

// RevokeConsent revokes a previously granted consent by ID.
func (s *Service) RevokeConsent(ctx context.Context, consentID string) error {
	now := s.nowFunc()
	if err := s.consentRepo.Revoke(ctx, consentID, now); err != nil {
		return fmt.Errorf("revoke consent: %w", err)
	}
	return nil
}

// GetUserConsents returns all consent records for a user.
func (s *Service) GetUserConsents(ctx context.Context, userID string) ([]domain.ConsentRecord, error) {
	records, err := s.consentRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user consents: %w", err)
	}
	return records, nil
}

// GetConsentByType returns the consent record for a user and consent type.
func (s *Service) GetConsentByType(ctx context.Context, userID, consentType string) (*domain.ConsentRecord, error) {
	record, err := s.consentRepo.FindByUserIDAndType(ctx, userID, consentType)
	if err != nil {
		return nil, fmt.Errorf("get consent by type: %w", err)
	}
	return record, nil
}

// --- Data Export ---

// ExportUserData collects all user data across tables and serializes it as JSON.
func (s *Service) ExportUserData(ctx context.Context, userID string) ([]byte, error) {
	user, err := s.exportRepo.GetUserData(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export user data: %w", err)
	}

	// Redact sensitive fields for the export.
	user.PasswordHash = "[REDACTED]"

	oauthAccounts, err := s.exportRepo.GetOAuthAccounts(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export oauth accounts: %w", err)
	}

	refreshTokens, err := s.exportRepo.GetRefreshTokens(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export refresh tokens: %w", err)
	}

	consentRecords, err := s.exportRepo.GetConsentRecords(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("export consent records: %w", err)
	}

	export := &domain.UserDataExport{
		User:           user,
		OAuthAccounts:  oauthAccounts,
		RefreshTokens:  refreshTokens,
		ConsentRecords: consentRecords,
		ExportedAt:     s.nowFunc(),
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal user data export: %w", err)
	}
	return data, nil
}

// --- Account Deletion ---

// RequestDeletion initiates a GDPR account deletion request with a 30-day grace period.
func (s *Service) RequestDeletion(ctx context.Context, userID, reason string) (*domain.DeletionRequest, error) {
	// Check for existing pending request.
	existing, err := s.deletionRepo.FindPendingByUserID(ctx, userID)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("user %s: %w", userID, domain.ErrDeletionAlreadyRequested)
	}

	now := s.nowFunc()
	scheduledAt := now.AddDate(0, 0, domain.DeletionGracePeriodDays)

	req := &domain.DeletionRequest{
		ID:          uuid.New().String(),
		UserID:      userID,
		Status:      domain.DeletionStatusPending,
		Reason:      reason,
		RequestedAt: now,
		ScheduledAt: scheduledAt,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	created, err := s.deletionRepo.Create(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request deletion: %w", err)
	}
	return created, nil
}

// CancelDeletion cancels a pending deletion request.
func (s *Service) CancelDeletion(ctx context.Context, requestID, cancelledBy string) error {
	req, err := s.deletionRepo.FindByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("cancel deletion: %w", err)
	}

	if req.Status == domain.DeletionStatusCompleted {
		return domain.ErrDeletionAlreadyCompleted
	}
	if req.Status == domain.DeletionStatusCancelled {
		return domain.ErrDeletionNotCancellable
	}

	now := s.nowFunc()
	if err := s.deletionRepo.Cancel(ctx, requestID, cancelledBy, now); err != nil {
		return fmt.Errorf("cancel deletion: %w", err)
	}
	return nil
}

// GetDeletionRequest returns the most recent deletion request for a user.
func (s *Service) GetDeletionRequest(ctx context.Context, userID string) (*domain.DeletionRequest, error) {
	req, err := s.deletionRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get deletion request: %w", err)
	}
	return req, nil
}

// ExecutePendingDeletions processes all approved deletion requests that are past their grace period.
// It performs cascading cleanup: revoke tokens, delete sessions, anonymize audit logs,
// remove OAuth links, delete consent records, and soft-delete the user.
func (s *Service) ExecutePendingDeletions(ctx context.Context) (int, error) {
	now := s.nowFunc()
	requests, err := s.deletionRepo.FindDueForExecution(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("find due deletions: %w", err)
	}

	executed := 0
	for _, req := range requests {
		if err := s.executeUserDeletion(ctx, req.UserID); err != nil {
			return executed, fmt.Errorf("execute deletion for user %s: %w", req.UserID, err)
		}

		if err := s.deletionRepo.UpdateStatus(ctx, req.ID, domain.DeletionStatusCompleted, now); err != nil {
			return executed, fmt.Errorf("update deletion status for %s: %w", req.ID, err)
		}
		executed++
	}

	return executed, nil
}

// ApprovePendingDeletion approves a pending deletion request so it can be executed after the grace period.
func (s *Service) ApprovePendingDeletion(ctx context.Context, requestID string) error {
	now := s.nowFunc()
	if err := s.deletionRepo.UpdateStatus(ctx, requestID, domain.DeletionStatusApproved, now); err != nil {
		return fmt.Errorf("approve deletion: %w", err)
	}
	return nil
}

// executeUserDeletion performs the cascading cleanup for a single user.
func (s *Service) executeUserDeletion(ctx context.Context, userID string) error {
	// 1. Delete refresh tokens (revoke all sessions).
	if err := s.exportRepo.DeleteRefreshTokens(ctx, userID); err != nil {
		return fmt.Errorf("delete refresh tokens: %w", err)
	}

	// 2. Delete OAuth account links.
	if err := s.exportRepo.DeleteOAuthAccounts(ctx, userID); err != nil {
		return fmt.Errorf("delete oauth accounts: %w", err)
	}

	// 3. Delete consent records.
	if err := s.consentRepo.DeleteByUserID(ctx, userID); err != nil {
		return fmt.Errorf("delete consent records: %w", err)
	}

	// 4. Anonymize audit logs (preserve events but remove PII).
	if err := s.exportRepo.AnonymizeAuditLogs(ctx, userID); err != nil {
		return fmt.Errorf("anonymize audit logs: %w", err)
	}

	// 5. Soft-delete the user record (30-day retention before permanent deletion).
	if err := s.exportRepo.SoftDeleteUser(ctx, userID); err != nil {
		return fmt.Errorf("soft delete user: %w", err)
	}

	return nil
}

// --- Data Retention ---

// RetentionConfig holds configurable data retention policies.
type RetentionConfig struct {
	SoftDeletedUserRetentionDays int
	ExpiredTokenRetentionDays    int
}

// DefaultRetentionConfig returns the default retention configuration.
func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		SoftDeletedUserRetentionDays: 90,
		ExpiredTokenRetentionDays:    30,
	}
}

// CleanupExpiredData enforces data retention policies by removing data past its retention period.
func (s *Service) CleanupExpiredData(ctx context.Context, config RetentionConfig) (*RetentionResult, error) {
	result := &RetentionResult{}

	usersDeleted, err := s.exportRepo.DeleteExpiredSoftDeletedUsers(ctx, config.SoftDeletedUserRetentionDays)
	if err != nil {
		return nil, fmt.Errorf("cleanup expired users: %w", err)
	}
	result.UsersDeleted = usersDeleted

	tokensDeleted, err := s.exportRepo.DeleteExpiredRefreshTokens(ctx, config.ExpiredTokenRetentionDays)
	if err != nil {
		return nil, fmt.Errorf("cleanup expired tokens: %w", err)
	}
	result.TokensDeleted = tokensDeleted

	return result, nil
}

// RetentionResult holds the results of a data retention cleanup run.
type RetentionResult struct {
	UsersDeleted  int64
	TokensDeleted int64
}
