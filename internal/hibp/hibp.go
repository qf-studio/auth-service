// Package hibp implements the HaveIBeenPwned k-anonymity API for
// checking whether a password has appeared in known data breaches.
package hibp

import (
	"bufio"
	"context"
	"crypto/sha1" //#nosec G505 — SHA-1 is required by the HIBP API protocol, not used for security
	"fmt"
	"io"
	"net/http"
	"strings"
)

const apiURL = "https://api.pwnedpasswords.com/range/"

// BreachChecker determines whether a password has appeared in a data breach.
type BreachChecker interface {
	IsBreached(ctx context.Context, password string) (bool, error)
}

// Client checks passwords against the HIBP Pwned Passwords API using
// the k-anonymity model: only the first 5 characters of the SHA-1 hash
// are sent to the API.
type Client struct {
	httpClient *http.Client
	apiURL     string
}

// NewClient creates a new HIBP client with the given HTTP client.
func NewClient(httpClient *http.Client) *Client {
	return &Client{
		httpClient: httpClient,
		apiURL:     apiURL,
	}
}

// IsBreached checks whether the given password appears in the HIBP database.
// It uses the k-anonymity range API: SHA-1 hash the password, send the first
// 5 hex chars as prefix, then compare the returned suffixes.
func (c *Client) IsBreached(ctx context.Context, password string) (bool, error) {
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password))) //#nosec G401
	prefix := hash[:5]
	suffix := hash[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+prefix, nil)
	if err != nil {
		return false, fmt.Errorf("hibp: create request: %w", err)
	}
	req.Header.Set("User-Agent", "qf-studio-auth-service")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("hibp: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
	}

	return matchesSuffix(resp.Body, suffix)
}

// matchesSuffix scans the HIBP response body for a matching hash suffix.
// Each line is formatted as "SUFFIX:COUNT".
func matchesSuffix(body io.Reader, suffix string) (bool, error) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("hibp: scan response: %w", err)
	}
	return false, nil
}
