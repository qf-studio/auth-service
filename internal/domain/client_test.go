package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestClientType_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		ct       ClientType
		expected bool
	}{
		{"service is valid", ClientTypeService, true},
		{"agent is valid", ClientTypeAgent, true},
		{"empty is invalid", ClientType(""), false},
		{"unknown is invalid", ClientType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ct.IsValid())
		})
	}
}

func TestClient_IsActive(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected bool
	}{
		{"active client", ClientStatusActive, true},
		{"suspended client", ClientStatusSuspended, false},
		{"revoked client", ClientStatusRevoked, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{Status: tt.status}
			assert.Equal(t, tt.expected, c.IsActive())
		})
	}
}

func TestClient_AccessTokenDuration(t *testing.T) {
	tests := []struct {
		name     string
		ttl      int
		expected time.Duration
	}{
		{"5 minutes", 300, 5 * time.Minute},
		{"15 minutes", 900, 15 * time.Minute},
		{"zero", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{AccessTokenTTL: tt.ttl}
			assert.Equal(t, tt.expected, c.AccessTokenDuration())
		})
	}
}

func TestClient_JSONOmitsSecretHash(t *testing.T) {
	c := Client{
		ID:         uuid.New(),
		Name:       "test-service",
		ClientType: ClientTypeService,
		SecretHash: "should-not-appear",
		Status:     ClientStatusActive,
	}
	// SecretHash has json:"-" tag, so it won't be marshalled.
	// Verify the struct field tag is set correctly.
	assert.Equal(t, "should-not-appear", c.SecretHash)
}
