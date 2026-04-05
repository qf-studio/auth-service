package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// totpSecretBytes is the size of the TOTP secret (160 bits per RFC 4226 recommendation).
	totpSecretBytes = 20

	// totpDigits is the number of digits in a TOTP code.
	totpDigits = 6

	// totpPeriod is the time step in seconds.
	totpPeriod = 30

	// totpSkew is the number of periods to check before/after current (±1 window).
	totpSkew = 1
)

// generateTOTPSecret creates a new TOTP secret using crypto/rand and returns
// the base32-encoded secret and the otpauth:// URI.
func generateTOTPSecret(issuer, accountName string) (secret, url string, err error) {
	// Generate 160-bit (20-byte) random secret.
	rawSecret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(rawSecret); err != nil {
		return "", "", fmt.Errorf("crypto/rand: %w", err)
	}

	b32Secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecret)

	// Build the OTP key using pquerna/otp.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      totpPeriod,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		Secret:      rawSecret,
		SecretSize:  totpSecretBytes,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp key: %w", err)
	}

	return b32Secret, key.URL(), nil
}

// validateTOTPCode checks a TOTP code against the base32-encoded secret
// with a ±1 period skew window.
func validateTOTPCode(b32Secret, code string) bool {
	valid, _ := totp.ValidateCustom(code, b32Secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:     totpSkew,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid
}
