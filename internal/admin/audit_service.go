package admin

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/storage"
)

// AuditService implements api.AdminAuditService.
type AuditService struct {
	repo   storage.AuditRepository
	logger *zap.Logger
}

// NewAuditService creates a new admin audit service.
func NewAuditService(repo storage.AuditRepository, logger *zap.Logger) *AuditService {
	return &AuditService{
		repo:   repo,
		logger: logger,
	}
}

// ListEvents returns a paginated list of audit events matching the given filters.
func (s *AuditService) ListEvents(ctx context.Context, page, perPage int, filter api.AuditFilter) (*api.AdminAuditList, error) {
	offset := (page - 1) * perPage

	events, total, err := s.repo.List(ctx, perPage, offset, filter)
	if err != nil {
		s.logger.Error("list audit events failed", zap.Error(err))
		return nil, fmt.Errorf("list audit events: %w", api.ErrInternalError)
	}

	return &api.AdminAuditList{
		Events:  events,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}, nil
}
