package domain

import "time"

// ConsentType represents the kind of consent being tracked.
type ConsentType string

const (
	ConsentTypeTermsOfService ConsentType = "terms_of_service"
	ConsentTypePrivacyPolicy  ConsentType = "privacy_policy"
	ConsentTypeMarketing      ConsentType = "marketing"
	ConsentTypeAnalytics      ConsentType = "analytics"
	ConsentTypeDataProcessing ConsentType = "data_processing"
)

// validConsentTypes is the authoritative set of recognised consent types.
var validConsentTypes = map[ConsentType]bool{
	ConsentTypeTermsOfService: true,
	ConsentTypePrivacyPolicy:  true,
	ConsentTypeMarketing:      true,
	ConsentTypeAnalytics:      true,
	ConsentTypeDataProcessing: true,
}

// IsValid returns true if the ConsentType is a recognised value.
func (ct ConsentType) IsValid() bool {
	return validConsentTypes[ct]
}

// String returns the string representation of the ConsentType.
func (ct ConsentType) String() string {
	return string(ct)
}

// DeletionStatus represents the lifecycle state of a GDPR deletion request.
type DeletionStatus string

const (
	DeletionStatusPending   DeletionStatus = "pending"
	DeletionStatusCompleted DeletionStatus = "completed"
	DeletionStatusCancelled DeletionStatus = "cancelled"
)

// validDeletionStatuses is the authoritative set of recognised deletion statuses.
var validDeletionStatuses = map[DeletionStatus]bool{
	DeletionStatusPending:   true,
	DeletionStatusCompleted: true,
	DeletionStatusCancelled: true,
}

// IsValid returns true if the DeletionStatus is a recognised value.
func (ds DeletionStatus) IsValid() bool {
	return validDeletionStatuses[ds]
}

// String returns the string representation of the DeletionStatus.
func (ds DeletionStatus) String() string {
	return string(ds)
}

// ConsentRecord tracks a user's consent grant or revocation for a specific type.
type ConsentRecord struct {
	ID          string      `json:"id"`
	UserID      string      `json:"user_id"`
	ConsentType ConsentType `json:"consent_type"`
	Granted     bool        `json:"granted"`
	GrantedAt   *time.Time  `json:"granted_at,omitempty"`
	RevokedAt   *time.Time  `json:"revoked_at,omitempty"`
	IPAddress   string      `json:"ip_address,omitempty"`
	UserAgent   string      `json:"user_agent,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// IsGranted returns true if the consent is currently active (granted and not revoked).
func (cr *ConsentRecord) IsGranted() bool {
	return cr.Granted && cr.RevokedAt == nil
}

// DeletionRequest represents a GDPR right-to-erasure request with grace-period workflow.
type DeletionRequest struct {
	ID           string         `json:"id"`
	UserID       string         `json:"user_id"`
	Status       DeletionStatus `json:"status"`
	Reason       string         `json:"reason,omitempty"`
	RequestedAt  time.Time      `json:"requested_at"`
	ScheduledAt  time.Time      `json:"scheduled_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	CancelledAt  *time.Time     `json:"cancelled_at,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// IsPending returns true if the deletion request is still pending execution.
func (dr *DeletionRequest) IsPending() bool {
	return dr.Status == DeletionStatusPending
}

// IsCancellable returns true if the deletion request can still be cancelled.
func (dr *DeletionRequest) IsCancellable() bool {
	return dr.Status == DeletionStatusPending && time.Now().Before(dr.ScheduledAt)
}
