package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Default HTTP server timeouts (HTTP_READ_TIMEOUT, HTTP_WRITE_TIMEOUT,
// HTTP_IDLE_TIMEOUT). WriteTimeout matches the default REQUEST_TIMEOUT so a
// handler that runs to its deadline can still write its response.
const (
	DefaultHTTPReadTimeout  = 15 * time.Second
	DefaultHTTPWriteTimeout = 30 * time.Second
	DefaultHTTPIdleTimeout  = 120 * time.Second
)

// MinSecretBytes is the minimum length of PASSWORD_PEPPER and of each
// SYSTEM_SECRETS entry in production.
const MinSecretBytes = 32

// placeholderPrefixes mark the example values shipped in the public
// .env*.example files (compared case-insensitively).
var placeholderPrefixes = []string{"change-me", "change_me"}

// Validate checks the production guardrails.
//
// With APP_ENV=production and CONFIG_STRICT=true any violation is returned as
// an error and startup must stop. Otherwise (non-strict, or any other
// APP_ENV) violations are returned as warnings, one per violated rule, for the
// caller to log. Messages never contain secret values.
func (c *Config) Validate() (warnings []string, err error) {
	violations := c.guardrailViolations()
	if len(violations) == 0 {
		return nil, nil
	}
	if c.App.Env == "production" && c.App.Strict {
		return nil, fmt.Errorf("production guardrails failed (CONFIG_STRICT=true): %s", strings.Join(violations, "; "))
	}
	return violations, nil
}

func (c *Config) guardrailViolations() []string {
	var v []string

	if !slices.Contains([]string{"require", "verify-ca", "verify-full"}, c.Postgres.SSLMode) {
		v = append(v, fmt.Sprintf("POSTGRES_SSLMODE=%q: must be require, verify-ca or verify-full", c.Postgres.SSLMode))
	}
	if c.Redis.Password == "" {
		v = append(v, "REDIS_PASSWORD: must be set")
	}
	if !c.Redis.TLS {
		v = append(v, "REDIS_TLS: must be true")
	}
	if msg := weakSecret(c.Argon2.Pepper); msg != "" {
		v = append(v, "PASSWORD_PEPPER: "+msg)
	}
	for i, s := range c.JWT.SystemSecrets {
		if msg := weakSecret(s); msg != "" {
			v = append(v, fmt.Sprintf("SYSTEM_SECRETS: entry %d: %s", i+1, msg))
		}
	}
	if !c.Email.Enabled {
		v = append(v, "EMAIL_ENABLED: must be true (otherwise reset and verification emails are only logged)")
	}
	return v
}

// weakSecret returns why s is unacceptable as a production secret, or "".
func weakSecret(s string) string {
	if len(s) < MinSecretBytes {
		return fmt.Sprintf("shorter than %d bytes", MinSecretBytes)
	}
	lower := strings.ToLower(s)
	for _, p := range placeholderPrefixes {
		if strings.HasPrefix(lower, p) {
			return "is a placeholder value"
		}
	}
	return ""
}
