package domain

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
)

// RFC 9396 Rich Authorization Requests (RAR) constants.
const (
	// RARTypePaymentInitiation is the RFC 9396 registered type for payment initiation.
	RARTypePaymentInitiation = "payment_initiation"

	// RARTypeAccountInformation is the RFC 9396 registered type for account information.
	RARTypeAccountInformation = "account_information"

	// RARTypeOpenIDCredential is the type for OpenID credential issuance.
	RARTypeOpenIDCredential = "openid_credential"

	// RARMaxLocations is the maximum number of locations per authorization detail.
	RARMaxLocations = 10

	// RARMaxActions is the maximum number of actions per authorization detail.
	RARMaxActions = 20

	// RARMaxDataTypes is the maximum number of datatypes per authorization detail.
	RARMaxDataTypes = 20

	// RARTypeMaxLength is the maximum length for the type field.
	RARTypeMaxLength = 255
)

// rarTypePattern matches valid RFC 9396 type identifiers:
// lowercase letters, digits, underscores, and hyphens.
var rarTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,254}$`)

// AuthorizationDetail represents a single RFC 9396 authorization_details entry.
// The "type" field is mandatory per the spec; all other fields are optional
// and depend on the authorization type definition.
type AuthorizationDetail struct {
	// Type is the required authorization type identifier (e.g., "payment_initiation").
	Type string `json:"type"`

	// Locations restricts the resources where this authorization applies (URIs).
	Locations []string `json:"locations,omitempty"`

	// Actions are the operations permitted (type-specific semantics).
	Actions []string `json:"actions,omitempty"`

	// DataTypes are the kinds of data being authorized (type-specific semantics).
	DataTypes []string `json:"datatypes,omitempty"`

	// Identifier is an opaque string identifying the specific resource instance.
	Identifier string `json:"identifier,omitempty"`

	// Extra holds additional type-specific fields not covered by the common set.
	Extra json.RawMessage `json:"extra,omitempty"`
}

// Validate checks that the AuthorizationDetail conforms to RFC 9396 constraints.
func (ad *AuthorizationDetail) Validate() error {
	if ad.Type == "" {
		return fmt.Errorf("authorization_details: %w", ErrRARTypeMissing)
	}
	if !rarTypePattern.MatchString(ad.Type) {
		return fmt.Errorf("authorization_details type %q: %w", ad.Type, ErrRARTypeInvalid)
	}
	if len(ad.Locations) > RARMaxLocations {
		return fmt.Errorf("authorization_details locations count %d: %w", len(ad.Locations), ErrRARTooManyLocations)
	}
	if len(ad.Actions) > RARMaxActions {
		return fmt.Errorf("authorization_details actions count %d: %w", len(ad.Actions), ErrRARTooManyActions)
	}
	if len(ad.DataTypes) > RARMaxDataTypes {
		return fmt.Errorf("authorization_details datatypes count %d: %w", len(ad.DataTypes), ErrRARTooManyDataTypes)
	}
	return nil
}

// ValidateAuthorizationDetails validates a slice of AuthorizationDetail entries.
func ValidateAuthorizationDetails(details []AuthorizationDetail) error {
	for i := range details {
		if err := details[i].Validate(); err != nil {
			return fmt.Errorf("authorization_details[%d]: %w", i, err)
		}
	}
	return nil
}

// RARResourceType represents a registered authorization type in the schema registry.
// Clients must be allowed to use specific types via the client_rar_allowed_types join table.
type RARResourceType struct {
	// ID is the primary key.
	ID uuid.UUID `json:"id"`

	// TenantID scopes this resource type to a tenant.
	TenantID string `json:"tenant_id"`

	// Type is the unique authorization type identifier (e.g., "payment_initiation").
	Type string `json:"type"`

	// Description is a human-readable explanation of what this type authorizes.
	Description string `json:"description"`

	// AllowedActions lists the valid actions for this type. Empty means any action is allowed.
	AllowedActions []string `json:"allowed_actions,omitempty"`

	// AllowedDataTypes lists the valid datatypes for this type. Empty means any datatype is allowed.
	AllowedDataTypes []string `json:"allowed_datatypes,omitempty"`

	// CreatedAt is the time this type was registered.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the time this type was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// ClientRARAllowedType represents the association between a client and the
// authorization types it is permitted to request.
type ClientRARAllowedType struct {
	// ClientID references the OAuth2 client.
	ClientID uuid.UUID `json:"client_id"`

	// TenantID scopes this association to a tenant.
	TenantID string `json:"tenant_id"`

	// ResourceTypeID references the RAR resource type.
	ResourceTypeID uuid.UUID `json:"resource_type_id"`

	// CreatedAt is when the permission was granted.
	CreatedAt time.Time `json:"created_at"`
}
