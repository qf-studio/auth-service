package authclient

import (
	"crypto/tls"
	"time"
)

const (
	defaultTimeout        = 5 * time.Second
	defaultMaxRetries     = 3
	defaultInitialBackoff = 100 * time.Millisecond
	defaultMaxBackoff     = 2 * time.Second
	defaultBackoffFactor  = 2.0
)

// options holds client configuration populated via functional options.
type options struct {
	timeout        time.Duration
	maxRetries     int
	initialBackoff time.Duration
	maxBackoff     time.Duration
	backoffFactor  float64
	tlsConfig      *tls.Config
	insecure       bool
}

func defaultOptions() options {
	return options{
		timeout:        defaultTimeout,
		maxRetries:     defaultMaxRetries,
		initialBackoff: defaultInitialBackoff,
		maxBackoff:     defaultMaxBackoff,
		backoffFactor:  defaultBackoffFactor,
	}
}

// Option configures the authclient.
type Option func(*options)

// WithTimeout sets the per-RPC timeout. Defaults to 5s.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
	}
}

// WithRetry configures exponential-backoff retry behaviour.
// maxRetries = 0 disables retries.
func WithRetry(maxRetries int, initialBackoff, maxBackoff time.Duration, factor float64) Option {
	return func(o *options) {
		o.maxRetries = maxRetries
		o.initialBackoff = initialBackoff
		o.maxBackoff = maxBackoff
		o.backoffFactor = factor
	}
}

// WithTLS sets the TLS configuration used for the gRPC connection.
// Mutually exclusive with WithInsecure.
func WithTLS(cfg *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = cfg
	}
}

// WithInsecure disables TLS. Only for development / testing.
func WithInsecure() Option {
	return func(o *options) {
		o.insecure = true
	}
}
