package domain

import "strings"

// NormalizeEmail returns the canonical form of an email address used for
// storage and comparison: surrounding whitespace trimmed and lower-cased.
//
// Decision: the whole address is lower-cased (not just the domain). RFC 5321
// permits case-sensitive local parts, but no mainstream provider honors that,
// and treating "Alice@x.com" and "alice@x.com" as distinct accounts is an
// account-confusion and duplicate-registration hazard.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
