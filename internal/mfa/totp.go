package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/qf-studio/auth-service/internal/domain"
)

// GenerateSecret creates a cryptographically random 160-bit TOTP secret
// and returns it as a base32-encoded string.
func GenerateSecret() (string, error) {
	secret := make([]byte, domain.TOTPSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateProvisioningURI creates an otpauth:// URI for QR code enrollment.
// The issuer identifies the service and accountName identifies the user.
func GenerateProvisioningURI(secret, issuer, accountName string) (string, error) {
	key, err := otp.NewKeyFromURL(
		fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
			issuer, accountName, secret, issuer,
			domain.TOTPAlgorithm, domain.TOTPDigits, domain.TOTPPeriod),
	)
	if err != nil {
		return "", fmt.Errorf("generate provisioning uri: %w", err)
	}
	return key.URL(), nil
}

// ValidateCode checks whether a TOTP code is valid for the given secret,
// using a ±1 step skew window to account for clock drift.
func ValidateCode(secret, code string) bool {
	return ValidateCodeAt(secret, code, time.Now())
}

// ValidateCodeAt checks whether a TOTP code is valid at the given time.
func ValidateCodeAt(secret, code string, t time.Time) bool {
	valid, _ := totp.ValidateCustom(code, secret, t, totp.ValidateOpts{
		Period:    uint(domain.TOTPPeriod),
		Skew:     uint(domain.TOTPSkew),
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}

// GenerateCodeAt generates a TOTP code for the given secret at the specified time.
// This is primarily useful for testing.
func GenerateCodeAt(secret string, t time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, t, totp.ValidateOpts{
		Period:    uint(domain.TOTPPeriod),
		Skew:     uint(domain.TOTPSkew),
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}
