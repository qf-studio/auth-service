package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/metrics"
	"github.com/qf-studio/auth-service/internal/storage"
)

// DashboardService implements api.AdminDashboardService.
type DashboardService struct {
	auditRepo     storage.AuditRepository
	dashboardRepo storage.DashboardRepository
	metrics       *metrics.Collector
	health        *health.Service
	logger        *zap.Logger
}

// NewDashboardService creates a new admin dashboard service.
func NewDashboardService(
	auditRepo storage.AuditRepository,
	dashboardRepo storage.DashboardRepository,
	metricsCollector *metrics.Collector,
	healthSvc *health.Service,
	logger *zap.Logger,
) *DashboardService {
	return &DashboardService{
		auditRepo:     auditRepo,
		dashboardRepo: dashboardRepo,
		metrics:       metricsCollector,
		health:        healthSvc,
		logger:        logger,
	}
}

// Overview returns system-level metrics for the admin dashboard.
func (s *DashboardService) Overview(ctx context.Context) (*api.DashboardOverview, error) {
	overview := &api.DashboardOverview{}

	// Active sessions (non-revoked, non-expired refresh tokens).
	sessions, err := s.dashboardRepo.CountActiveSessions(ctx)
	if err != nil {
		s.logger.Error("dashboard: count active sessions", zap.Error(err))
		return nil, fmt.Errorf("overview: %w", api.ErrInternalError)
	}
	overview.ActiveSessions = sessions

	// Active users in the last 24 hours (distinct actors with login_success events).
	since24h := time.Now().UTC().Add(-24 * time.Hour)
	activeUsers, err := s.auditRepo.DistinctActors(ctx,
		[]string{audit.EventLoginSuccess, audit.EventTokenRefresh}, since24h)
	if err != nil {
		s.logger.Error("dashboard: distinct active users", zap.Error(err))
		return nil, fmt.Errorf("overview: %w", api.ErrInternalError)
	}
	overview.ActiveUsers24h = activeUsers

	// Total users.
	totalUsers, err := s.dashboardRepo.CountUsers(ctx)
	if err != nil {
		s.logger.Error("dashboard: count users", zap.Error(err))
		return nil, fmt.Errorf("overview: %w", api.ErrInternalError)
	}
	overview.TotalUsers = totalUsers

	// Total clients.
	totalClients, err := s.dashboardRepo.CountClients(ctx)
	if err != nil {
		s.logger.Error("dashboard: count clients", zap.Error(err))
		return nil, fmt.Errorf("overview: %w", api.ErrInternalError)
	}
	overview.TotalClients = totalClients

	// Auth success rate from metrics.
	overview.AuthSuccessRate = s.computeAuthSuccessRate()

	// MFA adoption rate.
	if totalUsers > 0 {
		mfaCount, mfaErr := s.dashboardRepo.CountMFAEnabledUsers(ctx)
		if mfaErr != nil {
			s.logger.Error("dashboard: count mfa users", zap.Error(mfaErr))
			return nil, fmt.Errorf("overview: %w", api.ErrInternalError)
		}
		overview.MFAAdoptionRate = float64(mfaCount) / float64(totalUsers) * 100
	}

	// System health.
	healthResp := s.health.Health(ctx)
	overview.SystemHealth = string(healthResp.Status)

	return overview, nil
}

// Security returns security insight metrics for the admin dashboard.
func (s *DashboardService) Security(ctx context.Context) (*api.DashboardSecurity, error) {
	sec := &api.DashboardSecurity{}
	since24h := time.Now().UTC().Add(-24 * time.Hour)

	// Failed logins in last 24h.
	failedCount, err := s.auditRepo.CountByType(ctx, audit.EventLoginFailure, since24h)
	if err != nil {
		s.logger.Error("dashboard: count failed logins", zap.Error(err))
		return nil, fmt.Errorf("security: %w", api.ErrInternalError)
	}
	sec.FailedLogins24h = failedCount

	// Top targeted accounts.
	topAccounts, err := s.auditRepo.TopTargetedAccounts(ctx, audit.EventLoginFailure, since24h, 10)
	if err != nil {
		s.logger.Error("dashboard: top targeted accounts", zap.Error(err))
		return nil, fmt.Errorf("security: %w", api.ErrInternalError)
	}
	sec.TopTargetedAccounts = make([]api.AuditCountItem, 0, len(topAccounts))
	for _, a := range topAccounts {
		sec.TopTargetedAccounts = append(sec.TopTargetedAccounts, api.AuditCountItem{
			ID:    a.ID,
			Count: a.Count,
		})
	}

	// Top source IPs.
	topIPs, err := s.auditRepo.TopSourceIPs(ctx, audit.EventLoginFailure, since24h, 10)
	if err != nil {
		s.logger.Error("dashboard: top source ips", zap.Error(err))
		return nil, fmt.Errorf("security: %w", api.ErrInternalError)
	}
	sec.TopSourceIPs = make([]api.AuditCountItem, 0, len(topIPs))
	for _, ip := range topIPs {
		sec.TopSourceIPs = append(sec.TopSourceIPs, api.AuditCountItem{
			ID:    ip.ID,
			Count: ip.Count,
		})
	}

	// Locked accounts.
	lockedCount, err := s.dashboardRepo.CountLockedUsers(ctx)
	if err != nil {
		s.logger.Error("dashboard: count locked users", zap.Error(err))
		return nil, fmt.Errorf("security: %w", api.ErrInternalError)
	}
	sec.LockedAccounts = lockedCount

	// Recent security events.
	securityEventTypes := []string{
		audit.EventLoginFailure,
		audit.EventAdminUserLock,
		audit.EventAdminUserDelete,
		audit.EventAdminClientDelete,
		audit.EventAdminAPIKeyRevoke,
		audit.EventPasswordReused,
		audit.EventMFAMaxAttempts,
	}
	recentEvents, err := s.auditRepo.RecentByTypes(ctx, securityEventTypes, 20)
	if err != nil {
		s.logger.Error("dashboard: recent security events", zap.Error(err))
		return nil, fmt.Errorf("security: %w", api.ErrInternalError)
	}
	sec.RecentSecurityEvents = make([]api.AuditLogEntry, 0, len(recentEvents))
	for _, e := range recentEvents {
		sec.RecentSecurityEvents = append(sec.RecentSecurityEvents, auditEntryToAPI(e))
	}

	return sec, nil
}

// ListAuditLogs returns paginated audit log entries with optional filters.
func (s *DashboardService) ListAuditLogs(
	ctx context.Context,
	page, perPage int,
	action, actorID, severity string,
	startDate, endDate *time.Time,
) (*api.AuditLogList, error) {
	offset := (page - 1) * perPage

	filter := storage.AuditLogFilter{
		Action:    action,
		ActorID:   actorID,
		StartDate: startDate,
		EndDate:   endDate,
		Severity:  severity,
	}

	entries, total, err := s.auditRepo.List(ctx, perPage, offset, filter)
	if err != nil {
		s.logger.Error("dashboard: list audit logs", zap.Error(err))
		return nil, fmt.Errorf("list audit logs: %w", api.ErrInternalError)
	}

	result := &api.AuditLogList{
		Entries: make([]api.AuditLogEntry, 0, len(entries)),
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	for _, e := range entries {
		result.Entries = append(result.Entries, auditEntryToAPI(e))
	}

	return result, nil
}

// computeAuthSuccessRate calculates the auth success rate from the metrics collector.
func (s *DashboardService) computeAuthSuccessRate() float64 {
	snap, ok := s.metrics.JSONExport().(metrics.JSONSnapshot)
	if !ok {
		return 0
	}

	var successes, failures int64
	for key, count := range snap.AuthEvents {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		eventType, outcome := parts[0], parts[1]
		if eventType != "login_attempts_total" {
			continue
		}
		switch outcome {
		case "success":
			successes += count
		case "failure":
			failures += count
		}
	}

	total := successes + failures
	if total == 0 {
		return 100
	}
	return float64(successes) / float64(total) * 100
}

// auditEntryToAPI converts a storage audit entry to an API audit log entry.
func auditEntryToAPI(e *storage.AuditEntry) api.AuditLogEntry {
	return api.AuditLogEntry{
		ID:        e.ID,
		EventType: e.EventType,
		ActorID:   e.ActorID,
		TargetID:  e.TargetID,
		IP:        e.IP,
		Severity:  e.Severity,
		Metadata:  e.Metadata,
		CreatedAt: e.CreatedAt,
	}
}
