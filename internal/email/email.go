// Package email provides an interface and implementations for sending transactional emails.
//
// Two implementations are available:
//   - ConsoleSender: logs the message via zap (development / testing)
//   - HTTPSender:    delivers via the email-service REST API (production)
package email

import "context"

// Message is the payload passed to EmailSender.Send.
type Message struct {
	To      string
	Subject string
	Body    string
}

// EmailSender is the single method expected by callers that need to send email.
// Both ConsoleSender and HTTPSender satisfy this interface.
type EmailSender interface {
	Send(ctx context.Context, msg Message) error
}
