package oidc

import "context"

// Store abstracts the ephemeral persistence needed by the OIDC provider:
// login/consent challenges and one-time authorization codes. It is a narrow
// interface satisfied by *RedisStore, kept separate so ProviderService and
// ConsentService can be unit-tested without a real Redis instance (or, as in
// this package's own tests, exercised against *RedisStore backed by
// miniredis).
type Store interface {
	SaveLoginRequest(ctx context.Context, lr *LoginRequest) error
	GetLoginRequest(ctx context.Context, challenge string) (*LoginRequest, error)
	ConsumeLoginRequest(ctx context.Context, challenge string) (*LoginRequest, error)

	SaveConsentRequest(ctx context.Context, cr *ConsentRequest) error
	GetConsentRequest(ctx context.Context, challenge string) (*ConsentRequest, error)
	ConsumeConsentRequest(ctx context.Context, challenge string) (*ConsentRequest, error)

	SaveAuthorizationCode(ctx context.Context, ac *AuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
}

// Compile-time assertion that *RedisStore satisfies Store.
var _ Store = (*RedisStore)(nil)
