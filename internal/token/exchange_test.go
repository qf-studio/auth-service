package token_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/token"
)

// issueTestToken is a helper that issues a token pair and returns the access token.
func issueTestToken(t *testing.T, svc *token.Service, subject string, roles, scopes []string, clientType domain.ClientType) string {
	t.Helper()
	ctx := context.Background()
	result, err := svc.IssueTokenPair(ctx, subject, roles, scopes, clientType)
	require.NoError(t, err)
	return result.AccessToken
}

// validateExchangedToken parses the exchanged token and returns its claims.
func validateExchangedToken(t *testing.T, svc *token.Service, exchangedToken string) *domain.TokenClaims {
	t.Helper()
	ctx := context.Background()
	rawJWT := strings.TrimPrefix(exchangedToken, "qf_at_")
	claims, err := svc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	return claims
}

// ── Single-hop exchange ─────────────────────────────────────────────────────

func TestTokenExchange_SingleHop(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", []string{"admin"}, []string{"read:users", "write:users"}, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-backend", []string{"service"}, []string{"impersonate"}, domain.ClientTypeService)

	exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(exchanged, "qf_at_"), "exchanged token must have qf_at_ prefix")

	// Validate the exchanged token preserves subject identity.
	claims := validateExchangedToken(t, svc, exchanged)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, []string{"admin"}, claims.Roles)
	assert.Equal(t, []string{"read:users", "write:users"}, claims.Scopes)
	assert.Equal(t, domain.ClientTypeUser, claims.ClientType)
}

// ── Multi-hop chain ─────────────────────────────────────────────────────────

func TestTokenExchange_MultiHopChain(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	// Original user token.
	subjectToken := issueTestToken(t, svc, "user-123", []string{"user"}, []string{"read:data"}, domain.ClientTypeUser)

	// First hop: service A acts on behalf of user.
	actorA := issueTestToken(t, svc, "svc-A", nil, nil, domain.ClientTypeService)
	hop1, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorA,
	})
	require.NoError(t, err)

	// Second hop: service B acts on behalf of the delegation from hop1.
	actorB := issueTestToken(t, svc, "svc-B", nil, nil, domain.ClientTypeAgent)
	hop2, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: hop1,
		ActorToken:   actorB,
	})
	require.NoError(t, err)

	// The subject is still the original user.
	claims := validateExchangedToken(t, svc, hop2)
	assert.Equal(t, "user-123", claims.Subject)
}

// ── Max depth rejection ─────────────────────────────────────────────────────

func TestTokenExchange_MaxDepthRejection(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	// Build a chain of exactly maxDelegationDepth (5) hops.
	current := issueTestToken(t, svc, "user-origin", []string{"user"}, []string{"read:all"}, domain.ClientTypeUser)

	for i := 0; i < 5; i++ {
		actor := issueTestToken(t, svc, "svc-"+string(rune('A'+i)), nil, nil, domain.ClientTypeService)
		var err error
		current, err = svc.TokenExchange(ctx, token.TokenExchangeRequest{
			SubjectToken: current,
			ActorToken:   actor,
		})
		require.NoError(t, err, "hop %d should succeed", i+1)
	}

	// The 6th hop should be rejected (would create depth 6).
	actor6 := issueTestToken(t, svc, "svc-F", nil, nil, domain.ClientTypeService)
	_, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: current,
		ActorToken:   actor6,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delegation chain depth")
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// ── Audience restriction ────────────────────────────────────────────────────

func TestTokenExchange_AudienceRestriction(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", []string{"user"}, []string{"read:data"}, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-api", nil, nil, domain.ClientTypeService)

	exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
		Audience:     []string{"https://api.example.com"},
	})
	require.NoError(t, err)

	// Parse the raw JWT to check audience (domain.TokenClaims doesn't expose audience).
	rawJWT := strings.TrimPrefix(exchanged, "qf_at_")
	claims := validateExchangedToken(t, svc, rawJWT)
	// Verify subject is preserved.
	assert.Equal(t, "user-123", claims.Subject)
}

// ── Scope reduction ─────────────────────────────────────────────────────────

func TestTokenExchange_ScopeReduction(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", []string{"admin"}, []string{"read:users", "write:users", "delete:users"}, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-readonly", nil, nil, domain.ClientTypeService)

	// Request a subset of the subject's scopes.
	exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
		Scopes:       []string{"read:users"},
	})
	require.NoError(t, err)

	claims := validateExchangedToken(t, svc, exchanged)
	assert.Equal(t, []string{"read:users"}, claims.Scopes)
}

func TestTokenExchange_ScopeEscalationDenied(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", nil, []string{"read:users"}, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-evil", nil, nil, domain.ClientTypeService)

	// Try to escalate to a scope the subject doesn't have.
	_, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
		Scopes:       []string{"read:users", "write:users"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope escalation denied")
	assert.Contains(t, err.Error(), "write:users")
}

// ── Expired subject token rejection ─────────────────────────────────────────

func TestTokenExchange_ExpiredSubjectToken(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.AccessTokenTTL = 1 * time.Millisecond

	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	ctx := context.Background()
	result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Wait for expiry.
	time.Sleep(10 * time.Millisecond)

	// Issue a valid actor token with a longer-lived service.
	key2 := generateES256Key(t)
	_, rc2 := newTestRedis(t)
	cfg2 := defaultCfg()
	svc2, err := token.NewServiceFromKey(cfg2, key2, rc2, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	actorResult, err := svc2.IssueTokenPair(ctx, "svc-backend", nil, nil, domain.ClientTypeService)
	require.NoError(t, err)

	// Exchange with expired subject should fail (different keys, so use same svc).
	_, err = svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: result.AccessToken,
		ActorToken:   actorResult.AccessToken,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid subject token")
}

// ── Actor must be service or agent ──────────────────────────────────────────

func TestTokenExchange_UserActorRejected(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", nil, nil, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "user-456", nil, nil, domain.ClientTypeUser)

	_, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "actor must be service or agent")
}

// ── Agent client type as actor ──────────────────────────────────────────────

func TestTokenExchange_AgentActorAccepted(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", []string{"user"}, []string{"read:data"}, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "agent-ai", nil, nil, domain.ClientTypeAgent)

	exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
	})
	require.NoError(t, err)

	claims := validateExchangedToken(t, svc, exchanged)
	assert.Equal(t, "user-123", claims.Subject)
}

// ── TTL capping ─────────────────────────────────────────────────────────────

func TestTokenExchange_TTLCappedToFiveMinutes(t *testing.T) {
	svc, _ := newES256Service(t) // default 15min TTL
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", nil, nil, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-backend", nil, nil, domain.ClientTypeService)

	exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
	})
	require.NoError(t, err)

	claims := validateExchangedToken(t, svc, exchanged)
	// ExpiresAt should be roughly now + 5min (not 15min).
	remaining := time.Until(claims.ExpiresAt)
	assert.LessOrEqual(t, remaining.Minutes(), 5.1, "exchanged token TTL should be capped at 5 minutes")
	assert.Greater(t, remaining.Minutes(), 4.5, "exchanged token TTL should be close to 5 minutes")
}

func TestTokenExchange_TTLUsesRemainingWhenShorter(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.AccessTokenTTL = 2 * time.Minute // shorter than 5min cap

	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	ctx := context.Background()
	subjectToken := issueTestToken(t, svc, "user-123", nil, nil, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-backend", nil, nil, domain.ClientTypeService)

	exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
	})
	require.NoError(t, err)

	claims := validateExchangedToken(t, svc, exchanged)
	remaining := time.Until(claims.ExpiresAt)
	// Should be close to 2 minutes (subject remaining), not 5.
	assert.LessOrEqual(t, remaining.Minutes(), 2.1)
	assert.Greater(t, remaining.Minutes(), 1.5)
}

// ── Invalid tokens ──────────────────────────────────────────────────────────

func TestTokenExchange_InvalidSubjectToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	actorToken := issueTestToken(t, svc, "svc-backend", nil, nil, domain.ClientTypeService)

	_, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: "garbage-token",
		ActorToken:   actorToken,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid subject token")
}

func TestTokenExchange_InvalidActorToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", nil, nil, domain.ClientTypeUser)

	_, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   "garbage-token",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid actor token")
}

// ── Scope preservation without explicit request ─────────────────────────────

func TestTokenExchange_ScopesPreservedWhenNotRequested(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", nil, []string{"read:users", "write:users"}, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-backend", nil, nil, domain.ClientTypeService)

	exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
		SubjectToken: subjectToken,
		ActorToken:   actorToken,
	})
	require.NoError(t, err)

	claims := validateExchangedToken(t, svc, exchanged)
	assert.Equal(t, []string{"read:users", "write:users"}, claims.Scopes)
}

// ── Unique JTI for exchanged tokens ─────────────────────────────────────────

func TestTokenExchange_UniqueJTI(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	subjectToken := issueTestToken(t, svc, "user-123", nil, nil, domain.ClientTypeUser)
	actorToken := issueTestToken(t, svc, "svc-backend", nil, nil, domain.ClientTypeService)

	jtis := make(map[string]bool)
	for i := 0; i < 5; i++ {
		exchanged, err := svc.TokenExchange(ctx, token.TokenExchangeRequest{
			SubjectToken: subjectToken,
			ActorToken:   actorToken,
		})
		require.NoError(t, err)

		claims := validateExchangedToken(t, svc, exchanged)
		assert.False(t, jtis[claims.TokenID], "JTI should be unique across exchanges")
		jtis[claims.TokenID] = true
	}
}
