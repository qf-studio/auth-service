package domain

import "time"

// MFASecret represents a user's MFA enrollment (e.g. TOTP secret).
type MFASecret struct {
	ID          string
	UserID      string
	Type        string // "totp", "webauthn" (Phase 2)
	Secret      string // encrypted TOTP secret
	Confirmed   bool
	ConfirmedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

// BackupCode represents a single hashed MFA backup code.
type BackupCode struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	UsedAt    *time.Time
	CreatedAt time.Time
}

// MFAStatus summarises whether MFA is enabled for a user.
type MFAStatus struct {
	UserID     string
	Enabled    bool
	Type       string // active MFA type, empty if not enabled
	Confirmed  bool
	BackupLeft int // remaining unused backup codes
}

// WebAuthnCredential represents a registered WebAuthn credential (passkey / security key).
type WebAuthnCredential struct {
	ID              string     // UUID primary key
	UserID          string     // owning user
	CredentialID    []byte     // raw credential ID from authenticator
	PublicKey       []byte     // CBOR-encoded public key
	AttestationType string     // "none", "packed", etc.
	AAGUID          []byte     // authenticator attestation GUID (16 bytes)
	SignCount       uint32     // monotonic sign counter for clone detection
	Transports      []string   // e.g. ["usb", "nfc", "ble", "internal"]
	Name            string     // user-friendly label
	CreatedAt       time.Time
	LastUsedAt      *time.Time
	DeletedAt       *time.Time
}
