# authclient

Go SDK for calling the auth service's gRPC API (port 4002): token validation,
introspection, user lookup and permission checks, with timeouts and retries.

```go
c, err := authclient.New("auth-service:4002",
    authclient.WithTLS(tlsCfg),
    authclient.WithServiceToken(os.Getenv("AUTH_GRPC_TOKEN")),
)
if err != nil { /* ... */ }
defer c.Close()

res, err := c.ValidateToken(ctx, accessToken)
```

## Options

| Option | Purpose |
|--------|---------|
| `WithTimeout(d)` | Per-RPC timeout (default 5s) |
| `WithRetry(n, initial, max, factor)` | Exponential-backoff retries on transient errors; `n = 0` disables |
| `WithTLS(cfg)` | TLS configuration (default: system roots) |
| `WithInsecure()` | Plaintext, development and tests only |
| `WithServiceToken(token)` | Sends `authorization: Bearer <token>` on every call |

## Service token

The server's `GRPC_AUTH_MODE` is `warn` by default (unauthenticated calls are
allowed but logged) and becomes `enforce` per deployment, after which calls
without a valid token fail with `codes.Unauthenticated`. Ask the operator for a
token from the deployment's `GRPC_CLIENT_TOKENS`, keep it in your secret store,
and pass it with `WithServiceToken`. The token is sent in cleartext under
`WithInsecure`, so use `WithTLS` anywhere but local development. See
[gRPC Caller Authentication](../../deployments/README.md#grpc-caller-authentication)
for the rollout.
