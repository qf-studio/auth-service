// Package authclient provides a Go SDK for verifying tokens issued by the auth service.
package authclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

// Client wraps the gRPC AuthService client with helper methods, retry logic,
// and connection lifecycle management.
type Client struct {
	conn   *grpc.ClientConn
	auth   authv1.AuthServiceClient
	opts   options
}

// New dials the auth-service at target and returns a ready Client.
// target follows gRPC name-resolution syntax (e.g. "auth-service:4002").
func New(target string, optFns ...Option) (*Client, error) {
	opts := defaultOptions()
	for _, fn := range optFns {
		fn(&opts)
	}

	dialOpts, err := buildDialOpts(opts)
	if err != nil {
		return nil, fmt.Errorf("authclient: build dial options: %w", err)
	}

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("authclient: dial %s: %w", target, err)
	}

	return &Client{
		conn: conn,
		auth: authv1.NewAuthServiceClient(conn),
		opts: opts,
	}, nil
}

// NewFromConn creates a Client from an existing *grpc.ClientConn.
// Intended for testing with in-process servers (bufconn).
func NewFromConn(conn *grpc.ClientConn, optFns ...Option) *Client {
	opts := defaultOptions()
	for _, fn := range optFns {
		fn(&opts)
	}
	return &Client{
		conn: conn,
		auth: authv1.NewAuthServiceClient(conn),
		opts: opts,
	}
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// buildDialOpts assembles grpc.DialOption slice from client options.
func buildDialOpts(opts options) ([]grpc.DialOption, error) {
	var dialOpts []grpc.DialOption

	switch {
	case opts.insecure:
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	case opts.tlsConfig != nil:
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(opts.tlsConfig)))
	default:
		// Default to system TLS pool.
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	}

	return dialOpts, nil
}

// withTimeout returns a context that expires after the configured timeout.
func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.opts.timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.opts.timeout)
}

// retryable reports whether a gRPC status code should trigger a retry.
// Only transient errors are retried; application-level errors are not.
func retryable(code codes.Code) bool {
	switch code {
	case codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded:
		return true
	default:
		return false
	}
}

// do executes fn with exponential-backoff retries on transient gRPC errors.
func (c *Client) do(ctx context.Context, fn func(ctx context.Context) error) error {
	backoff := c.opts.initialBackoff
	var lastErr error

	for attempt := 0; attempt <= c.opts.maxRetries; attempt++ {
		callCtx, cancel := c.withTimeout(ctx)
		lastErr = fn(callCtx)
		cancel()

		if lastErr == nil {
			return nil
		}

		// Don't retry if the parent context is done.
		if ctx.Err() != nil {
			return lastErr
		}

		code := status.Code(lastErr)
		if !retryable(code) {
			return lastErr
		}

		if attempt < c.opts.maxRetries {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
			backoff = time.Duration(float64(backoff) * c.opts.backoffFactor)
			if backoff > c.opts.maxBackoff {
				backoff = c.opts.maxBackoff
			}
		}
	}

	return lastErr
}
