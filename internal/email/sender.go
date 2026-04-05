// Package email provides email sending abstractions for the auth service.
// It supports a console sender for development (logs emails) and an HTTP
// sender that calls the email-service REST API in production.
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Sender is the interface for sending transactional emails.
type Sender interface {
	// SendVerificationEmail sends an email verification link to the user.
	SendVerificationEmail(ctx context.Context, to, token string) error

	// SendPasswordReset sends a password reset link to the user.
	SendPasswordReset(ctx context.Context, to, token string) error

	// SendAccountLockout notifies the user that their account has been locked.
	SendAccountLockout(ctx context.Context, to, reason string) error

	// SendMFAEnrollment notifies the user about MFA enrollment status.
	SendMFAEnrollment(ctx context.Context, to string) error
}

// ConsoleSender logs emails to the console instead of sending them.
// Used in development and testing environments.
type ConsoleSender struct {
	logger *zap.Logger
}

// NewConsoleSender creates a new ConsoleSender.
func NewConsoleSender(logger *zap.Logger) *ConsoleSender {
	return &ConsoleSender{logger: logger}
}

func (s *ConsoleSender) SendVerificationEmail(_ context.Context, to, token string) error {
	s.logger.Info("email: verification",
		zap.String("to", to),
		zap.String("token", token),
	)
	return nil
}

func (s *ConsoleSender) SendPasswordReset(_ context.Context, to, token string) error {
	s.logger.Info("email: password reset",
		zap.String("to", to),
		zap.String("token", token),
	)
	return nil
}

func (s *ConsoleSender) SendAccountLockout(_ context.Context, to, reason string) error {
	s.logger.Info("email: account lockout",
		zap.String("to", to),
		zap.String("reason", reason),
	)
	return nil
}

func (s *ConsoleSender) SendMFAEnrollment(_ context.Context, to string) error {
	s.logger.Info("email: MFA enrollment",
		zap.String("to", to),
	)
	return nil
}

// HTTPSender sends emails via the email-service REST API.
type HTTPSender struct {
	client     *http.Client
	baseURL    string
	apiKey     string
	fromAddr   string
	logger     *zap.Logger
}

// NewHTTPSender creates a new HTTPSender.
func NewHTTPSender(baseURL, apiKey, fromAddr string, logger *zap.Logger) *HTTPSender {
	return &HTTPSender{
		client: &http.Client{Timeout: 10 * time.Second},
		baseURL:  baseURL,
		apiKey:   apiKey,
		fromAddr: fromAddr,
		logger:   logger,
	}
}

type emailRequest struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

func (s *HTTPSender) SendVerificationEmail(ctx context.Context, to, token string) error {
	return s.send(ctx, to, "Verify your email address",
		fmt.Sprintf("Please verify your email by using this token: %s", token))
}

func (s *HTTPSender) SendPasswordReset(ctx context.Context, to, token string) error {
	return s.send(ctx, to, "Reset your password",
		fmt.Sprintf("Use this token to reset your password: %s", token))
}

func (s *HTTPSender) SendAccountLockout(ctx context.Context, to, reason string) error {
	return s.send(ctx, to, "Account locked",
		fmt.Sprintf("Your account has been locked. Reason: %s", reason))
}

func (s *HTTPSender) SendMFAEnrollment(ctx context.Context, to string) error {
	return s.send(ctx, to, "MFA enrollment",
		"Multi-factor authentication has been configured for your account.")
}

func (s *HTTPSender) send(ctx context.Context, to, subject, body string) error {
	payload := emailRequest{
		From:    s.fromAddr,
		To:      to,
		Subject: subject,
		Body:    body,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal email request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/send", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("create email request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		s.logger.Error("email service returned error",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(respBody)),
		)
		return fmt.Errorf("email service returned status %d", resp.StatusCode)
	}

	return nil
}

// NopSender is a no-op email sender used when email is disabled.
type NopSender struct{}

func (NopSender) SendVerificationEmail(context.Context, string, string) error { return nil }
func (NopSender) SendPasswordReset(context.Context, string, string) error     { return nil }
func (NopSender) SendAccountLockout(context.Context, string, string) error    { return nil }
func (NopSender) SendMFAEnrollment(context.Context, string) error             { return nil }
