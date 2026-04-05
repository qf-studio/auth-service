package domain

import "time"

// WebAuthnCredential represents a stored WebAuthn credential (public key credential source).
type WebAuthnCredential struct {
	ID              string // UUID primary key
	UserID          string // FK to users table
	CredentialID    []byte // Raw credential ID from authenticator
	PublicKey       []byte // COSE-encoded public key
	AttestationType string // Attestation format (e.g. "none", "packed")
	AAGUID          []byte // Authenticator Attestation GUID
	SignCount       uint32 // Signature counter for clone detection
	CloneWarning    bool   // True if sign count regression detected
	Name            string // User-friendly credential name
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}
