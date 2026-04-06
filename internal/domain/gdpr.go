package domain

import "time"

// ConsentType represents the type of GDPR consent.
const (
	ConsentTypeDataProcessing = "data_processing"
	ConsentTypeMarketing      = "marketing"
	ConsentTypeAnalytics      = "analytics"
	ConsentTypeThirdParty     = "third_party"
)

// DeletionStatus represents the state of a GDPR deletion request.
const (
	DeletionStatusPending   = "pending"
	DeletionStatusApproved  = "approved"
	DeletionStatusCompleted = "completed"
	DeletionStatusCancelled = "cancelled"
)

// DeletionGracePeriodDays is the number of days before a deletion request is executed.
const DeletionGracePeriodDays = 30

// ConsentRecord tracks a user's GDPR consent grant or revocation.
type ConsentRecord struct {
	ID          string
	UserID      string
	ConsentType string
	Granted     bool
	IPAddress   string
	UserAgent   string
	GrantedAt   *time.Time
	RevokedAt   *time.Time
	CreatedAt   time.Time
}

// DeletionRequest tracks a GDPR account deletion request with grace period.
type DeletionRequest struct {
	ID          string
	UserID      string
	Status      string
	Reason      string
	RequestedAt time.Time
	ScheduledAt time.Time
	CompletedAt *time.Time
	CancelledAt *time.Time
	CancelledBy *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// IsPending returns true if the deletion request is still pending.
func (d *DeletionRequest) IsPending() bool {
	return d.Status == DeletionStatusPending
}

// IsCompleted returns true if the deletion request has been executed.
func (d *DeletionRequest) IsCompleted() bool {
	return d.Status == DeletionStatusCompleted
}

// IsCancelled returns true if the deletion request was cancelled.
func (d *DeletionRequest) IsCancelled() bool {
	return d.Status == DeletionStatusCancelled
}

// UserDataExport represents the aggregated data export for a user.
type UserDataExport struct {
	User           *User                `json:"user"`
	OAuthAccounts  []OAuthAccount       `json:"oauth_accounts"`
	RefreshTokens  []RefreshTokenRecord `json:"refresh_tokens"`
	ConsentRecords []ConsentRecord      `json:"consent_records"`
	ExportedAt     time.Time            `json:"exported_at"`
}

// DataRetentionPolicy defines how long different types of data are retained.
type DataRetentionPolicy struct {
	Name          string
	RetentionDays int
	Description   string
}
