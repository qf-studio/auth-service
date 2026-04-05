package email

import (
	"context"

	"go.uber.org/zap"
)

// ConsoleSender implements EmailSender by writing the message to the zap logger.
// Intended for development and test environments where email delivery is not required.
type ConsoleSender struct {
	logger *zap.Logger
}

// NewConsoleSender returns a ConsoleSender backed by the given logger.
func NewConsoleSender(logger *zap.Logger) *ConsoleSender {
	return &ConsoleSender{logger: logger}
}

// Send logs the email message at info level. It never returns an error.
func (s *ConsoleSender) Send(_ context.Context, msg Message) error {
	s.logger.Info("email (console)",
		zap.String("to", msg.To),
		zap.String("subject", msg.Subject),
		zap.String("body", msg.Body),
	)
	return nil
}
