package authclient

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Client provides token validation and permission checking against the
// QuantFlow auth service gRPC API.
type Client struct {
	conn   *grpc.ClientConn
	rpc    authv1.AuthServiceClient
	opts   *clientOptions
	target string
}

// New creates a new Client connected to the given target address.
// The target uses standard gRPC naming (e.g., "localhost:4002").
func New(target string, options ...Option) (*Client, error) {
	opts := defaultOptions()
	for _, o := range options {
		o(opts)
	}

	conn, err := grpc.NewClient(target, opts.dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("authclient: dial %s: %w", target, err)
	}

	return &Client{
		conn:   conn,
		rpc:    authv1.NewAuthServiceClient(conn),
		opts:   opts,
		target: target,
	}, nil
}

// NewFromConn wraps an existing gRPC client connection. The caller retains
// ownership of conn; Close on this Client is a no-op.
func NewFromConn(conn *grpc.ClientConn, options ...Option) *Client {
	opts := defaultOptions()
	for _, o := range options {
		o(opts)
	}

	return &Client{
		conn: conn,
		rpc:  authv1.NewAuthServiceClient(conn),
		opts: opts,
	}
}

// Close releases the underlying gRPC connection. It is safe to call
// multiple times. For clients created with NewFromConn, Close is a no-op.
func (c *Client) Close() error {
	if c.target == "" {
		// Created via NewFromConn; caller owns conn.
		return nil
	}
	return c.conn.Close()
}

// withDeadline creates a child context with the configured timeout if the
// parent does not already have a deadline.
func (c *Client) withDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.opts.timeout)
}

// retryDo executes fn with exponential backoff + jitter on transient gRPC errors.
func (c *Client) retryDo(ctx context.Context, fn func(ctx context.Context) error) error {
	var lastErr error

	for attempt := range c.opts.maxRetries + 1 {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		lastErr = err

		if !isRetryable(err) || attempt == c.opts.maxRetries {
			break
		}

		backoff := c.backoffDuration(attempt)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	return lastErr
}

// backoffDuration computes exponential backoff with jitter, capped at retryMax.
func (c *Client) backoffDuration(attempt int) time.Duration {
	base := float64(c.opts.retryBase)
	d := base * math.Pow(2, float64(attempt))
	if d > float64(c.opts.retryMax) {
		d = float64(c.opts.retryMax)
	}
	// Add +-25% jitter.
	jitter := d * 0.25 * (rand.Float64()*2 - 1)
	return time.Duration(d + jitter)
}

// isRetryable returns true for gRPC status codes that are safe to retry.
func isRetryable(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch s.Code() {
	case codes.Unavailable, codes.ResourceExhausted, codes.Aborted:
		return true
	default:
		return false
	}
}
