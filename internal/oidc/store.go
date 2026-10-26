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
	// ConsumeAuthorizationCode atomically redeems the code and leaves a
	// used-code record behind (GH-542).
	ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error)
	// RecordCodeIssuance stores the tokens issued from a redeemed code and
	// reports whether the code was presented again in the meantime, in which
	// case the caller must revoke those tokens. Returns ErrUsedCodeNotFound
	// if the used-code record is gone.
	RecordCodeIssuance(ctx context.Context, code string, iss CodeIssuance) (replayed bool, err error)
	// MarkCodeReplayed handles a presentation of an already-redeemed code. It
	// flags the used-code record as replayed and returns the tokens issued
	// from the code, or nil if the first redemption has not recorded them
	// yet (it will see the flag and revoke them itself). Returns
	// ErrUsedCodeNotFound if the code was never redeemed or the record has
	// expired.
	MarkCodeReplayed(ctx context.Context, code string) (*CodeIssuance, error)
}

// Compile-time assertion that *RedisStore satisfies Store.
var _ Store = (*RedisStore)(nil)
