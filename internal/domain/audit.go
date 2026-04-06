package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog represents a persisted audit event.
type AuditLog struct {
	ID        uuid.UUID
	EventType string
	ActorID   string
	TargetID  string
	IP        string
	Metadata  map[string]string
	CreatedAt time.Time
}
