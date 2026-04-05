package token

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	// maxDelegationDepth is the maximum allowed depth of the act claim chain.
	maxDelegationDepth = 5

	// exchangeMaxTTL is the maximum TTL for an exchanged token.
	exchangeMaxTTL = 5 * time.Minute
)

// TokenExchangeRequest contains the parameters for an RFC 8693 token exchange.
type TokenExchangeRequest struct {
	// SubjectToken is the access token representing the original subject.
	SubjectToken string

	// ActorToken is the access token of the service/agent performing delegation.
	ActorToken string

	// Audience restricts the exchanged token to this audience (optional).
	Audience []string

	// Scopes restricts the exchanged token to these scopes (must be subset of subject token scopes).
	Scopes []string
}

// TokenExchange implements RFC 8693 token exchange with delegation chain support.
// It validates the subject and actor tokens, enforces scope reduction and audience
// restriction, builds nested act claims, and issues a new access token.
func (s *Service) TokenExchange(ctx context.Context, req TokenExchangeRequest) (string, error) {
	// Validate subject token (must be a valid access token).
	subjectJWT := strings.TrimPrefix(req.SubjectToken, accessTokenPrefix)
	subjectClaims, err := s.parseAndVerifyJWT(subjectJWT)
	if err != nil {
		return "", fmt.Errorf("invalid subject token: %w", err)
	}

	// Validate actor token (must be a valid access token).
	actorJWT := strings.TrimPrefix(req.ActorToken, accessTokenPrefix)
	actorClaims, err := s.parseAndVerifyJWT(actorJWT)
	if err != nil {
		return "", fmt.Errorf("invalid actor token: %w", err)
	}

	// Actor must be service or agent client type.
	actorClientType := domain.ClientType(actorClaims.ClientType)
	if actorClientType != domain.ClientTypeService && actorClientType != domain.ClientTypeAgent {
		return "", fmt.Errorf("actor must be service or agent client type, got %q", actorClaims.ClientType)
	}

	// Build the new act claim: actor becomes the outermost, existing chain nests inside.
	newAct := &actorClaim{
		Subject:    actorClaims.Subject,
		ClientType: actorClaims.ClientType,
		Act:        subjectClaims.Act, // carry forward any existing delegation chain
	}

	// Enforce max delegation depth.
	depth := chainDepth(newAct)
	if depth > maxDelegationDepth {
		return "", fmt.Errorf("delegation chain depth %d exceeds maximum of %d", depth, maxDelegationDepth)
	}

	// Enforce scope reduction: requested scopes must be a subset of subject token scopes.
	exchangeScopes := subjectClaims.Scopes
	if len(req.Scopes) > 0 {
		if err := validateScopeReduction(subjectClaims.Scopes, req.Scopes); err != nil {
			return "", err
		}
		exchangeScopes = req.Scopes
	}

	// Compute TTL: min(remaining subject TTL, exchangeMaxTTL).
	subjectExp := subjectClaims.ExpiresAt.Time
	remaining := time.Until(subjectExp)
	if remaining <= 0 {
		return "", fmt.Errorf("subject token has expired")
	}
	ttl := remaining
	if ttl > exchangeMaxTTL {
		ttl = exchangeMaxTTL
	}

	// Generate JTI for the exchanged token.
	jti, err := generateRandomID(jtiBytes)
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := &customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subjectClaims.Subject,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
		Roles:      subjectClaims.Roles,
		Scopes:     exchangeScopes,
		ClientType: subjectClaims.ClientType,
		Act:        newAct,
	}

	// Enforce audience restriction.
	if len(req.Audience) > 0 {
		claims.Audience = req.Audience
	}

	token := jwt.NewWithClaims(s.signingMethod, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign exchanged token: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventTokenExchange,
		ActorID:  actorClaims.Subject,
		TargetID: subjectClaims.Subject,
		Metadata: map[string]string{
			"jti":         jti,
			"chain_depth": fmt.Sprintf("%d", depth),
		},
	})

	s.logger.Info("token exchanged",
		zap.String("subject", subjectClaims.Subject),
		zap.String("actor", actorClaims.Subject),
		zap.Int("chain_depth", depth),
		zap.Duration("ttl", ttl),
	)

	return accessTokenPrefix + signed, nil
}

// chainDepth returns the depth of an actor claim chain (1-indexed).
func chainDepth(act *actorClaim) int {
	depth := 0
	for a := act; a != nil; a = a.Act {
		depth++
	}
	return depth
}

// validateScopeReduction ensures that requested scopes are a subset of the
// subject token's scopes. Returns an error if any scope would escalate privileges.
func validateScopeReduction(subjectScopes, requestedScopes []string) error {
	allowed := make(map[string]bool, len(subjectScopes))
	for _, s := range subjectScopes {
		allowed[s] = true
	}
	for _, s := range requestedScopes {
		if !allowed[s] {
			return fmt.Errorf("scope %q not present in subject token (scope escalation denied)", s)
		}
	}
	return nil
}
