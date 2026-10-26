package token

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Refresh-token lifecycle state in Redis.
//
// Redis is the authoritative store for refresh tokens: `rt_sig:<key>` holds
// the live record and is consumed atomically (GETDEL) on rotation. Two more
// keys make revocation and rotation safe:
//
//   - `rt_epoch:<subject>`: unix-nano timestamp. Every refresh record issued
//     at or before it is invalid. Setting it revokes all of a subject's
//     refresh tokens in O(1) without a per-user index. TTL = refresh TTL,
//     after which every older record has expired anyway.
//   - `rt_used:<key>`: written when a record is rotated. Presenting a rotated
//     token again (outside a short leeway for client retries) revokes every
//     refresh token of that subject, so a copied token cannot keep a parallel
//     chain alive next to the legitimate client.
const (
	refreshEpochKeyPrefix = "rt_epoch:"
	refreshUsedKeyPrefix  = "rt_used:"

	// refreshReuseLeeway is how long after rotation a second presentation of
	// the same refresh token is treated as a benign client retry (rejected,
	// without revoking the subject's other tokens).
	refreshReuseLeeway = 5 * time.Second
)

// errRefreshReused marks a rotated refresh token presented again.
var errRefreshReused = errors.New("refresh token already used")

// usedRefreshRecord is the value of an `rt_used:<key>` tombstone.
type usedRefreshRecord struct {
	Subject string `json:"sub"`
	UsedAt  int64  `json:"used_at"`
}

// RevokeAllRefreshTokens invalidates every refresh token issued to subject
// up to now. Used by logout-all, password reset/change, email change/revert,
// and refresh-token reuse.
func (s *Service) RevokeAllRefreshTokens(ctx context.Context, subject string) error {
	if subject == "" {
		return fmt.Errorf("revoke all refresh tokens: empty subject")
	}
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := s.redis.Set(ctx, refreshEpochKeyPrefix+subject, now, s.cfg.RefreshTokenTTL).Err(); err != nil {
		return fmt.Errorf("revoke all refresh tokens: %w", err)
	}
	return nil
}

// refreshEpoch returns the subject's revocation epoch (unix nanos), or 0.
func (s *Service) refreshEpoch(ctx context.Context, subject string) (int64, error) {
	raw, err := s.redis.Get(ctx, refreshEpochKeyPrefix+subject).Result()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("lookup refresh epoch: %w", err)
	}
	epoch, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse refresh epoch: %w", err)
	}
	return epoch, nil
}

// refreshKeyFromToken verifies the HMAC of rawToken against every system
// secret (newest first, for rotation) and returns the encoded key part.
func (s *Service) refreshKeyFromToken(rawToken string) (string, error) {
	token := strings.TrimPrefix(rawToken, refreshTokenPrefix)

	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed refresh token")
	}
	keyEncoded, sigEncoded := parts[0], parts[1]

	keyMaterial, err := base64.RawURLEncoding.DecodeString(keyEncoded)
	if err != nil {
		return "", fmt.Errorf("decode refresh key: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return "", fmt.Errorf("decode refresh signature: %w", err)
	}

	for _, secret := range s.cfg.SystemSecrets {
		if hmac.Equal(sigBytes, hmacSign(keyMaterial, secret)) {
			return keyEncoded, nil
		}
	}
	return "", fmt.Errorf("invalid refresh token signature")
}

// decodeRefreshRecord parses an `rt_sig:<key>` value. Records written before
// GH-512 hold the bare subject string; they carry no issue time.
func decodeRefreshRecord(raw string) refreshTokenData {
	var data refreshTokenData
	if err := json.Unmarshal([]byte(raw), &data); err != nil || data.Subject == "" {
		return refreshTokenData{Subject: raw}
	}
	return data
}

// lookupRefreshToken verifies rawToken and returns its live record without
// consuming it. A missing record is checked against the rotation tombstone:
// a rotated token presented again after refreshReuseLeeway revokes all of
// the subject's refresh tokens and returns errRefreshReused.
func (s *Service) lookupRefreshToken(ctx context.Context, rawToken string) (string, refreshTokenData, error) {
	keyEncoded, err := s.refreshKeyFromToken(rawToken)
	if err != nil {
		return "", refreshTokenData{}, err
	}

	raw, err := s.redis.Get(ctx, refreshKeyPrefix+keyEncoded).Result()
	if errors.Is(err, redis.Nil) {
		return "", refreshTokenData{}, s.checkRefreshReuse(ctx, keyEncoded)
	}
	if err != nil {
		return "", refreshTokenData{}, fmt.Errorf("lookup refresh token: %w", err)
	}

	data := decodeRefreshRecord(raw)
	epoch, err := s.refreshEpoch(ctx, data.Subject)
	if err != nil {
		return "", refreshTokenData{}, err
	}
	if epoch != 0 && data.IssuedAt <= epoch {
		// Revoked by a revoke-all; drop the record so it is not checked again.
		_ = s.redis.Del(ctx, refreshKeyPrefix+keyEncoded).Err()
		return "", refreshTokenData{}, fmt.Errorf("refresh token revoked")
	}
	return keyEncoded, data, nil
}

// checkRefreshReuse handles a refresh token whose live record is gone.
func (s *Service) checkRefreshReuse(ctx context.Context, keyEncoded string) error {
	raw, err := s.redis.Get(ctx, refreshUsedKeyPrefix+keyEncoded).Result()
	if errors.Is(err, redis.Nil) {
		return fmt.Errorf("refresh token not found or expired")
	}
	if err != nil {
		return fmt.Errorf("lookup used refresh token: %w", err)
	}

	var used usedRefreshRecord
	if err := json.Unmarshal([]byte(raw), &used); err != nil || used.Subject == "" {
		return errRefreshReused
	}
	if time.Since(time.Unix(0, used.UsedAt)) <= refreshReuseLeeway {
		return errRefreshReused
	}

	if err := s.RevokeAllRefreshTokens(ctx, used.Subject); err != nil {
		s.logger.Error("failed to revoke refresh tokens after reuse",
			zap.String("subject", used.Subject), zap.Error(err))
	}
	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventTokenRevoke,
		ActorID:  used.Subject,
		TargetID: used.Subject,
		Metadata: map[string]string{"reason": "refresh_token_reuse"},
	})
	s.logger.Warn("rotated refresh token presented again; revoked all refresh tokens for subject",
		zap.String("subject", used.Subject))
	return errRefreshReused
}

// consumeRefreshToken atomically removes the live record for keyEncoded and
// leaves a rotation tombstone. Returns errRefreshReused if another request
// consumed it first.
func (s *Service) consumeRefreshToken(ctx context.Context, keyEncoded, subject string) error {
	if err := s.redis.GetDel(ctx, refreshKeyPrefix+keyEncoded).Err(); err != nil {
		if errors.Is(err, redis.Nil) {
			return errRefreshReused
		}
		return fmt.Errorf("consume refresh token: %w", err)
	}

	tombstone, err := json.Marshal(usedRefreshRecord{Subject: subject, UsedAt: time.Now().UnixNano()})
	if err == nil {
		err = s.redis.Set(ctx, refreshUsedKeyPrefix+keyEncoded, tombstone, s.cfg.RefreshTokenTTL).Err()
	}
	if err != nil {
		s.logger.Warn("failed to record rotated refresh token", zap.String("subject", subject), zap.Error(err))
	}
	return nil
}

// revokeRefreshToken invalidates a single refresh token (RFC 7009 revocation
// and logout). An unknown or malformed token is not an error.
func (s *Service) revokeRefreshToken(ctx context.Context, rawToken string) error {
	keyEncoded, err := s.refreshKeyFromToken(rawToken)
	if err != nil {
		s.logger.Debug("revoke: not a valid refresh token, ignoring", zap.Error(err))
		return nil
	}
	if err := s.redis.Del(ctx, refreshKeyPrefix+keyEncoded).Err(); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	if s.refreshTokens != nil {
		if sig, ok := domain.RefreshTokenSignature(rawToken); ok {
			tenantID := domain.TenantIDFromContext(ctx)
			if err := s.refreshTokens.Revoke(ctx, tenantID, sig); err != nil && !errors.Is(err, storage.ErrNotFound) {
				s.logger.Warn("failed to revoke refresh token signature in db", zap.Error(err))
			}
		}
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventTokenRevoke,
		Metadata: map[string]string{"token_type": "refresh"},
	})
	return nil
}

// RevokingRefreshTokenRepository wraps the Postgres refresh-token repository
// so that RevokeAllForUser also invalidates the subject's refresh tokens in
// Redis, where refresh validity is decided. Callers that revoke all of a
// user's sessions (logout-all, password reset, email change/revert, admin)
// get both effects through the repository they already use.
type RevokingRefreshTokenRepository struct {
	storage.RefreshTokenRepository
	tokens *Service
}

// WrapRefreshTokenRepository returns repo wrapped by RevokingRefreshTokenRepository.
func (s *Service) WrapRefreshTokenRepository(repo storage.RefreshTokenRepository) *RevokingRefreshTokenRepository {
	return &RevokingRefreshTokenRepository{RefreshTokenRepository: repo, tokens: s}
}

// RevokeAllForUser invalidates the user's refresh tokens in Redis, then marks
// the Postgres rows revoked. The Redis step decides validity, so its failure
// is returned even if Postgres would succeed.
func (r *RevokingRefreshTokenRepository) RevokeAllForUser(ctx context.Context, tenantID uuid.UUID, userID string) error {
	if err := r.tokens.RevokeAllRefreshTokens(ctx, userID); err != nil {
		return err
	}
	return r.RefreshTokenRepository.RevokeAllForUser(ctx, tenantID, userID)
}
