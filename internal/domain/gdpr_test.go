package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConsentType_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		ct    ConsentType
		valid bool
	}{
		{"terms_of_service", ConsentTypeTermsOfService, true},
		{"privacy_policy", ConsentTypePrivacyPolicy, true},
		{"marketing", ConsentTypeMarketing, true},
		{"analytics", ConsentTypeAnalytics, true},
		{"data_processing", ConsentTypeDataProcessing, true},
		{"empty", ConsentType(""), false},
		{"unknown", ConsentType("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.ct.IsValid())
		})
	}
}

func TestConsentType_String(t *testing.T) {
	assert.Equal(t, "marketing", ConsentTypeMarketing.String())
}

func TestDeletionStatus_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		ds    DeletionStatus
		valid bool
	}{
		{"pending", DeletionStatusPending, true},
		{"completed", DeletionStatusCompleted, true},
		{"cancelled", DeletionStatusCancelled, true},
		{"empty", DeletionStatus(""), false},
		{"unknown", DeletionStatus("rejected"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.ds.IsValid())
		})
	}
}

func TestDeletionStatus_String(t *testing.T) {
	assert.Equal(t, "pending", DeletionStatusPending.String())
}

func TestConsentRecord_IsGranted(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		record  ConsentRecord
		granted bool
	}{
		{
			name:    "granted and not revoked",
			record:  ConsentRecord{Granted: true, GrantedAt: &now},
			granted: true,
		},
		{
			name:    "granted but revoked",
			record:  ConsentRecord{Granted: true, GrantedAt: &now, RevokedAt: &now},
			granted: false,
		},
		{
			name:    "not granted",
			record:  ConsentRecord{Granted: false},
			granted: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.granted, tt.record.IsGranted())
		})
	}
}

func TestDeletionRequest_IsPending(t *testing.T) {
	tests := []struct {
		name    string
		status  DeletionStatus
		pending bool
	}{
		{"pending", DeletionStatusPending, true},
		{"completed", DeletionStatusCompleted, false},
		{"cancelled", DeletionStatusCancelled, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dr := DeletionRequest{Status: tt.status}
			assert.Equal(t, tt.pending, dr.IsPending())
		})
	}
}

func TestDeletionRequest_IsCancellable(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	tests := []struct {
		name        string
		status      DeletionStatus
		scheduledAt time.Time
		cancellable bool
	}{
		{"pending and future scheduled", DeletionStatusPending, future, true},
		{"pending but past scheduled", DeletionStatusPending, past, false},
		{"completed", DeletionStatusCompleted, future, false},
		{"cancelled", DeletionStatusCancelled, future, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dr := DeletionRequest{Status: tt.status, ScheduledAt: tt.scheduledAt}
			assert.Equal(t, tt.cancellable, dr.IsCancellable())
		})
	}
}
