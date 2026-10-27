package email

import (
	"context"

	"go.uber.org/zap"
)

// ConsoleSender implements EmailSender by logging that a message would have
// been sent. Intended for development and test environments where email
// delivery is not required.
//
// Decision: the body is never logged — it carries single-use reset/verify
// links, which would otherwise end up in log aggregation.
type ConsoleSender struct {
	logger *zap.Logger
}

// NewConsoleSender returns a ConsoleSender backed by the given logger.
func NewConsoleSender(logger *zap.Logger) *ConsoleSender {
	return &ConsoleSender{logger: logger}
}

// Send logs the recipient and subject at info level. It never returns an error.
func (s *ConsoleSender) Send(_ context.Context, msg Message) error {
	s.logger.Info("email (console)",
		zap.String("to", msg.To),
		zap.String("subject", msg.Subject),
	)
	return nil
}
