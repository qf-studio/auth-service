// Package authclient provides a Go SDK for verifying tokens and checking
// permissions against the QuantFlow auth service over gRPC.
package authclient

import (
	"crypto/tls"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Option configures the Client.
type Option func(*clientOptions)

type clientOptions struct {
	dialOpts   []grpc.DialOption
	timeout    time.Duration
	maxRetries int
	retryBase  time.Duration
	retryMax   time.Duration
}

func defaultOptions() *clientOptions {
	return &clientOptions{
		timeout:    5 * time.Second,
		maxRetries: 3,
		retryBase:  100 * time.Millisecond,
		retryMax:   5 * time.Second,
	}
}

// WithTLS configures TLS credentials for the gRPC connection.
func WithTLS(cfg *tls.Config) Option {
	return func(o *clientOptions) {
		o.dialOpts = append(o.dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	}
}

// WithInsecure disables transport security. Use only for testing or
// localhost connections.
func WithInsecure() Option {
	return func(o *clientOptions) {
		o.dialOpts = append(o.dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// WithTimeout sets the per-RPC deadline. Default is 5s.
func WithTimeout(d time.Duration) Option {
	return func(o *clientOptions) {
		o.timeout = d
	}
}

// WithMaxRetries sets the maximum number of retry attempts for transient
// failures. Default is 3. Set to 0 to disable retries.
func WithMaxRetries(n int) Option {
	return func(o *clientOptions) {
		o.maxRetries = n
	}
}

// WithRetryBackoff configures the exponential backoff base and maximum
// durations. Default base is 100ms, max is 5s.
func WithRetryBackoff(base, max time.Duration) Option {
	return func(o *clientOptions) {
		o.retryBase = base
		o.retryMax = max
	}
}

// WithDialOptions appends arbitrary gRPC dial options.
func WithDialOptions(opts ...grpc.DialOption) Option {
	return func(o *clientOptions) {
		o.dialOpts = append(o.dialOpts, opts...)
	}
}
