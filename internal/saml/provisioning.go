package saml

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Provisioner handles JIT (Just-In-Time) user provisioning for SAML logins.
// It creates new users on first SAML login, maps SAML groups to internal roles,
// and links SAML identities to existing users by email match.
type Provisioner struct {
	users      storage.UserRepository
	identities storage.SAMLIdentityRepository
	logger     *zap.Logger
}

// NewProvisioner creates a Provisioner with the required dependencies.
func NewProvisioner(
	users storage.UserRepository,
	identities storage.SAMLIdentityRepository,
	logger *zap.Logger,
) *Provisioner {
	return &Provisioner{
		users:      users,
		identities: identities,
		logger:     logger,
	}
}

// ProvisionResult contains the outcome of a provisioning operation.
type ProvisionResult struct {
	// User is the provisioned or matched user.
	User *domain.User

	// Identity is the SAML identity link.
	Identity *domain.SAMLIdentity

	// Created is true if a new user was created (first SAML login).
	Created bool

	// Linked is true if a SAML identity was linked to an existing user by email.
	Linked bool
}

// Provision handles the JIT provisioning flow:
// 1. Look up existing SAML identity by IdP entity ID + NameID.
// 2. If found, return the linked user (returning login).
// 3. If not found, try to match by email (link SAML identity to existing user).
// 4. If no email match, create a new user and link the SAML identity.
func (p *Provisioner) Provision(ctx context.Context, assertion *ParsedAssertion, mapped MappedUser) (*ProvisionResult, error) {
	// Step 1: Check for existing SAML identity link.
	existing, err := p.identities.FindByIdPAndNameID(ctx, assertion.Issuer, assertion.NameID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("provision: find saml identity: %w", err)
	}

	if existing != nil {
		// Returning SAML user — load the linked user.
		user, err := p.users.FindByID(ctx, existing.UserID)
		if err != nil {
			return nil, fmt.Errorf("provision: find linked user: %w", err)
		}

		if !user.IsActive() {
			return nil, fmt.Errorf("provision: %w", domain.ErrAccountLocked)
		}

		// Update last login (best-effort).
		if err := p.users.UpdateLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
			p.logger.Error("failed to update last_login_at for SAML user",
				zap.String("user_id", user.ID), zap.Error(err))
		}

		return &ProvisionResult{
			User:     user,
			Identity: existing,
		}, nil
	}

	// Step 2: No existing SAML identity — try email match.
	if mapped.Email != "" {
		user, err := p.users.FindByEmail(ctx, mapped.Email)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("provision: find user by email: %w", err)
		}

		if user != nil {
			if !user.IsActive() {
				return nil, fmt.Errorf("provision: %w", domain.ErrAccountLocked)
			}

			// Link SAML identity to existing user.
			identity, err := p.createIdentity(ctx, user.ID, assertion)
			if err != nil {
				return nil, err
			}

			// Update last login (best-effort).
			if err := p.users.UpdateLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
				p.logger.Error("failed to update last_login_at for linked SAML user",
					zap.String("user_id", user.ID), zap.Error(err))
			}

			p.logger.Info("SAML identity linked to existing user by email",
				zap.String("user_id", user.ID),
				zap.String("idp", assertion.Issuer),
				zap.String("email", mapped.Email),
			)

			return &ProvisionResult{
				User:     user,
				Identity: identity,
				Linked:   true,
			}, nil
		}
	}

	// Step 3: No existing user — JIT create.
	if mapped.Email == "" {
		return nil, fmt.Errorf("provision: email is required for JIT user creation: %w", domain.ErrSAMLResponseInvalid)
	}

	now := time.Now().UTC()
	newUser := &domain.User{
		ID:            fmt.Sprintf("usr_%s", generateSAMLID()),
		Email:         mapped.Email,
		Name:          mapped.Name,
		Roles:         mapped.Roles,
		EmailVerified: true, // SAML-asserted emails are considered verified.
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	created, err := p.users.Create(ctx, newUser)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateEmail) {
			// Race condition: another request created the user between our check and create.
			return nil, fmt.Errorf("provision: user already exists with email %s: %w", mapped.Email, domain.ErrUserAlreadyExists)
		}
		return nil, fmt.Errorf("provision: create user: %w", err)
	}

	// Link SAML identity to the new user.
	identity, err := p.createIdentity(ctx, created.ID, assertion)
	if err != nil {
		return nil, err
	}

	p.logger.Info("JIT-provisioned new user via SAML",
		zap.String("user_id", created.ID),
		zap.String("idp", assertion.Issuer),
		zap.String("email", mapped.Email),
	)

	return &ProvisionResult{
		User:     created,
		Identity: identity,
		Created:  true,
	}, nil
}

// createIdentity creates and stores a SAML identity link.
func (p *Provisioner) createIdentity(ctx context.Context, userID string, assertion *ParsedAssertion) (*domain.SAMLIdentity, error) {
	identity := &domain.SAMLIdentity{
		ID:           fmt.Sprintf("sid_%s", generateSAMLID()),
		UserID:       userID,
		IdPEntityID:  assertion.Issuer,
		NameID:       assertion.NameID,
		SessionIndex: assertion.SessionIndex,
		Attributes:   assertion.Attributes,
		CreatedAt:    time.Now().UTC(),
	}

	created, err := p.identities.Create(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("provision: create saml identity: %w", err)
	}
	return created, nil
}

// generateSAMLID produces a random hex ID for SAML-related entities.
func generateSAMLID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
