package mocks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"time"
)

// EmailMessage is a captured send-email request.
type EmailMessage struct {
	From    string
	To      string
	Subject string
	Body    string
}

// EmailSinkMock fakes the email-service REST API that
// internal/email.HTTPSender calls (POST /send-email), capturing every
// message so tests can pull verification/reset links out of it instead of
// needing a real mail transport.
type EmailSinkMock struct {
	server *httptest.Server

	mu       sync.Mutex
	messages []EmailMessage
}

// sendEmailRequest mirrors internal/email.HTTPSender's wire format.
type sendEmailRequest struct {
	From      string   `json:"from"`
	To        []string `json:"to"`
	Subject   string   `json:"subject"`
	Body      string   `json:"body"`
	Transport string   `json:"transport"`
}

// NewEmailSinkMock starts the fake email-service server. Callers must Close
// it when done.
func NewEmailSinkMock() *EmailSinkMock {
	m := &EmailSinkMock{}
	mux := http.NewServeMux()
	mux.HandleFunc("/send-email", m.handleSend)
	m.server = httptest.NewServer(mux)
	return m
}

// URL returns the mock's base URL (no trailing slash), suitable for
// EMAIL_SERVICE_URL.
func (m *EmailSinkMock) URL() string { return m.server.URL }

// Port returns the TCP port the mock is listening on, for wiring
// container host-port access.
func (m *EmailSinkMock) Port() (int, error) { return serverPort(m.server) }

// Close shuts down the underlying httptest.Server.
func (m *EmailSinkMock) Close() { m.server.Close() }

func (m *EmailSinkMock) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req sendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var to string
	if len(req.To) > 0 {
		to = req.To[0]
	}

	m.mu.Lock()
	m.messages = append(m.messages, EmailMessage{
		From:    req.From,
		To:      to,
		Subject: req.Subject,
		Body:    req.Body,
	})
	m.mu.Unlock()

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"queued"}`))
}

// Messages returns a snapshot of all captured messages, in receipt order.
func (m *EmailSinkMock) Messages() []EmailMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]EmailMessage, len(m.messages))
	copy(out, m.messages)
	return out
}

// MessagesTo returns captured messages addressed to the given recipient, in
// receipt order.
func (m *EmailSinkMock) MessagesTo(to string) []EmailMessage {
	var out []EmailMessage
	for _, msg := range m.Messages() {
		if msg.To == to {
			out = append(out, msg)
		}
	}
	return out
}

// tokenLinkRe extracts the "token" query parameter from a verify-email /
// password-reset link, matching how internal/auth.Service builds
// "<base>?token=<token>" links in the email body.
var tokenLinkRe = regexp.MustCompile(`[?&]token=([^\s&]+)`)

// ExtractToken pulls the token query-parameter value out of body's first
// link-shaped match, if any.
func ExtractToken(body string) (string, bool) {
	match := tokenLinkRe.FindStringSubmatch(body)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// ExtractTokenFrom pulls the token query-parameter value out of the first
// link in body that starts with linkBase. Anchoring on the base matters:
// register and password-reset both email "<base>?token=<token>" links to
// the same address, and an unanchored extraction returns whichever email
// landed first (the register-time verification mail), not the one the
// caller is waiting for.
func ExtractTokenFrom(body, linkBase string) (string, bool) {
	re := regexp.MustCompile(regexp.QuoteMeta(linkBase) + `\?token=([^\s&]+)`)
	match := re.FindStringSubmatch(body)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// WaitForToken polls MessagesTo(to) until a message containing a token link
// starting with linkBase arrives or timeout elapses, returning the
// extracted token. The linkBase filter distinguishes verification emails
// from password-reset emails sent to the same recipient (see
// ExtractTokenFrom). Polling (not a fixed sleep) keeps this robust
// regardless of how long email delivery takes to land in the sink.
func (m *EmailSinkMock) WaitForToken(ctx context.Context, to, linkBase string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	const pollInterval = 50 * time.Millisecond

	for {
		for _, msg := range m.MessagesTo(to) {
			if token, ok := ExtractTokenFrom(msg.Body, linkBase); ok {
				return token, nil
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("mocks: no email with a %s?token= link received for %q within %s", linkBase, to, timeout)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
