// Package mocks provides fake external-service HTTP servers for the e2e
// suite: a HaveIBeenPwned range-endpoint stand-in, an email delivery sink,
// and a webhook receiver. Each wraps an httptest.Server so the real SUT
// container can reach it over the network (via testcontainers host-port
// access) exactly as it would reach the real external service, while the
// test process retains an in-memory handle for assertions.
package mocks

import (
	"crypto/sha1" //#nosec G505 — SHA-1 matches the HIBP k-anonymity protocol, not used for security
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

// HIBPMock fakes the HaveIBeenPwned Pwned Passwords k-anonymity range API
// (GET /range/{prefix}) that internal/hibp.Client calls. Suffixes are
// registered per 5-char SHA-1 prefix via MarkBreachedSuffix or
// MarkPasswordBreached; any prefix with nothing registered is a miss, just
// like the real API's "not found" response.
type HIBPMock struct {
	server *httptest.Server

	mu    sync.Mutex
	hits  map[string]map[string]int // prefix -> suffix -> occurrence count
	calls []string                  // prefixes requested, in request order
}

// NewHIBPMock starts the fake HIBP server. Callers must Close it when done.
func NewHIBPMock() *HIBPMock {
	m := &HIBPMock{hits: make(map[string]map[string]int)}
	mux := http.NewServeMux()
	mux.HandleFunc("/range/", m.handleRange)
	m.server = httptest.NewServer(mux)
	return m
}

// URL returns the mock's base URL (no trailing slash).
func (m *HIBPMock) URL() string { return m.server.URL }

// Port returns the TCP port the mock is listening on, for wiring
// container host-port access.
func (m *HIBPMock) Port() (int, error) { return serverPort(m.server) }

// Close shuts down the underlying httptest.Server.
func (m *HIBPMock) Close() { m.server.Close() }

// MarkBreachedSuffix registers prefix/suffix (both uppercase hex, matching
// SHA-1(password)[:5] / [5:]) as breached with the given occurrence count,
// so a subsequent range request for prefix includes suffix in its response.
func (m *HIBPMock) MarkBreachedSuffix(prefix, suffix string, count int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hits[prefix] == nil {
		m.hits[prefix] = make(map[string]int)
	}
	m.hits[prefix][suffix] = count
}

// MarkPasswordBreached is a convenience wrapper around MarkBreachedSuffix
// that computes the SHA-1 prefix/suffix for password itself, matching the
// exact hash internal/hibp.Client would send for that password.
func (m *HIBPMock) MarkPasswordBreached(password string, count int) {
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password))) //#nosec G401
	m.MarkBreachedSuffix(hash[:5], hash[5:], count)
}

// Requests returns the range-endpoint prefixes requested so far, in order.
func (m *HIBPMock) Requests() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *HIBPMock) handleRange(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/range/"))

	m.mu.Lock()
	m.calls = append(m.calls, prefix)
	suffixes := m.hits[prefix]
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	for suffix, count := range suffixes {
		_, _ = fmt.Fprintf(w, "%s:%d\r\n", suffix, count)
	}
}

// serverPort extracts the TCP port an httptest.Server is bound to from its
// URL, for wiring testcontainers.WithHostPortAccess.
func serverPort(server *httptest.Server) (int, error) {
	u, err := url.Parse(server.URL)
	if err != nil {
		return 0, fmt.Errorf("mocks: parse server URL %q: %w", server.URL, err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0, fmt.Errorf("mocks: parse server port from %q: %w", server.URL, err)
	}
	return port, nil
}
