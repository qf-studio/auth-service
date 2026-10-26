package password

import (
	"context"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/hibp"
)

// CheckNotBreached enforces the NIST SP 800-63-4 breached-password blocklist.
// It returns domain.ErrPasswordBreached when the password appears in a known
// breach.
//
// Decision: fail open. If the breach service errors or times out, the password
// is allowed, a WARN is logged and an audit event is emitted — availability of
// registration and password changes must not depend on a third-party API.
//
// A nil checker disables the check. flow names the calling flow in the audit
// metadata; actorID may be empty (e.g. registration).
func CheckNotBreached(ctx context.Context, checker hibp.BreachChecker, logger *zap.Logger, auditor audit.EventLogger, actorID, flow, pwd string) error {
	if checker == nil {
		return nil
	}

	breached, err := checker.IsBreached(ctx, pwd)
	if err != nil {
		logger.Warn("breached-password check unavailable; allowing password (fail open)",
			zap.String("flow", flow), zap.String("user_id", actorID), zap.Error(err))
		auditor.LogEvent(ctx, audit.Event{
			Type:     audit.EventBreachCheckFailed,
			ActorID:  actorID,
			TargetID: actorID,
			Metadata: map[string]string{"flow": flow},
		})
		return nil
	}
	if breached {
		auditor.LogEvent(ctx, audit.Event{
			Type:     audit.EventPasswordBreached,
			ActorID:  actorID,
			TargetID: actorID,
			Metadata: map[string]string{"flow": flow},
		})
		return domain.ErrPasswordBreached
	}
	return nil
}
