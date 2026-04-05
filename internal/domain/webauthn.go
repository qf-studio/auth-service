package domain

import "time"

// WebAuthnCredential represents a registered WebAuthn/FIDO2 credential for a user.
type WebAuthnCredential struct {
	ID              string     // unique internal identifier
	UserID          string     // owner
	CredentialID    []byte     // raw credential ID from the authenticator
	PublicKey       []byte     // COSE-encoded public key
	AAGUID          string     // authenticator attestation GUID (hex-encoded)
	SignCount       uint32     // signature counter for clone detection
	Transports      []string   // e.g. ["usb", "nfc", "ble", "internal"]
	AttestationType string     // "none", "indirect", "direct", "enterprise"
	FriendlyName    string     // user-assigned label (e.g. "YubiKey 5C")
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       *time.Time // soft-delete
}
