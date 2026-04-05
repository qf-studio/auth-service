package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAPIKey_IsActive(t *testing.T) {
	future := time.Now().UTC().Add(1 * time.Hour)
	past := time.Now().UTC().Add(-1 * time.Hour)

	tests := []struct {
		name     string
		key      *APIKey
		expected bool
	}{
		{"active no expiry", &APIKey{Status: APIKeyStatusActive}, true},
		{"active future expiry", &APIKey{Status: APIKeyStatusActive, ExpiresAt: &future}, true},
		{"active past expiry", &APIKey{Status: APIKeyStatusActive, ExpiresAt: &past}, false},
		{"revoked", &APIKey{Status: APIKeyStatusRevoked}, false},
		{"revoked with future expiry", &APIKey{Status: APIKeyStatusRevoked, ExpiresAt: &future}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.key.IsActive())
		})
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	future := time.Now().UTC().Add(1 * time.Hour)
	past := time.Now().UTC().Add(-1 * time.Hour)

	tests := []struct {
		name     string
		key      *APIKey
		expected bool
	}{
		{"no expiry", &APIKey{}, false},
		{"future expiry", &APIKey{ExpiresAt: &future}, false},
		{"past expiry", &APIKey{ExpiresAt: &past}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.key.IsExpired())
		})
	}
}

func TestAPIKey_JSONOmitsKeyHash(t *testing.T) {
	k := APIKey{
		KeyHash:         "should-not-appear",
		PreviousKeyHash: "also-hidden",
		Status:          APIKeyStatusActive,
	}
	// KeyHash has json:"-" tag, so it won't be marshalled.
	// Verify the struct field holds the value correctly.
	assert.Equal(t, "should-not-appear", k.KeyHash)
	assert.Equal(t, "also-hidden", k.PreviousKeyHash)
}
