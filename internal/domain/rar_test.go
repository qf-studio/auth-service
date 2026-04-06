package domain

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizationDetail_Validate(t *testing.T) {
	tests := []struct {
		name    string
		detail  AuthorizationDetail
		wantErr error
	}{
		{
			name:   "valid minimal detail",
			detail: AuthorizationDetail{Type: "payment_initiation"},
		},
		{
			name: "valid full detail",
			detail: AuthorizationDetail{
				Type:       "account_information",
				Locations:  []string{"https://api.example.com/accounts"},
				Actions:    []string{"read", "list"},
				DataTypes:  []string{"balance", "transactions"},
				Identifier: "acct-123",
			},
		},
		{
			name: "valid with extra field",
			detail: AuthorizationDetail{
				Type:  "payment_initiation",
				Extra: json.RawMessage(`{"amount":100}`),
			},
		},
		{
			name:    "missing type",
			detail:  AuthorizationDetail{},
			wantErr: ErrRARTypeMissing,
		},
		{
			name:    "invalid type - uppercase",
			detail:  AuthorizationDetail{Type: "Payment"},
			wantErr: ErrRARTypeInvalid,
		},
		{
			name:    "invalid type - starts with digit",
			detail:  AuthorizationDetail{Type: "1payment"},
			wantErr: ErrRARTypeInvalid,
		},
		{
			name:    "invalid type - spaces",
			detail:  AuthorizationDetail{Type: "payment initiation"},
			wantErr: ErrRARTypeInvalid,
		},
		{
			name:    "invalid type - too long",
			detail:  AuthorizationDetail{Type: strings.Repeat("a", 256)},
			wantErr: ErrRARTypeInvalid,
		},
		{
			name:   "valid type - max length",
			detail: AuthorizationDetail{Type: "a" + strings.Repeat("b", 254)},
		},
		{
			name:   "valid type - hyphens and underscores",
			detail: AuthorizationDetail{Type: "my-custom_type-v2"},
		},
		{
			name: "too many locations",
			detail: AuthorizationDetail{
				Type:      "payment_initiation",
				Locations: make([]string, RARMaxLocations+1),
			},
			wantErr: ErrRARTooManyLocations,
		},
		{
			name: "too many actions",
			detail: AuthorizationDetail{
				Type:    "payment_initiation",
				Actions: make([]string, RARMaxActions+1),
			},
			wantErr: ErrRARTooManyActions,
		},
		{
			name: "too many datatypes",
			detail: AuthorizationDetail{
				Type:      "payment_initiation",
				DataTypes: make([]string, RARMaxDataTypes+1),
			},
			wantErr: ErrRARTooManyDataTypes,
		},
		{
			name: "max locations is ok",
			detail: AuthorizationDetail{
				Type:      "payment_initiation",
				Locations: make([]string, RARMaxLocations),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.detail.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAuthorizationDetails(t *testing.T) {
	tests := []struct {
		name    string
		details []AuthorizationDetail
		wantErr bool
	}{
		{
			name:    "nil slice",
			details: nil,
		},
		{
			name:    "empty slice",
			details: []AuthorizationDetail{},
		},
		{
			name: "multiple valid",
			details: []AuthorizationDetail{
				{Type: "payment_initiation"},
				{Type: "account_information", Actions: []string{"read"}},
			},
		},
		{
			name: "second entry invalid",
			details: []AuthorizationDetail{
				{Type: "payment_initiation"},
				{Type: ""},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuthorizationDetails(tt.details)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "authorization_details[1]")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRARTypeConstants(t *testing.T) {
	// Ensure registered type constants are valid.
	for _, typeName := range []string{
		RARTypePaymentInitiation,
		RARTypeAccountInformation,
		RARTypeOpenIDCredential,
	} {
		t.Run(typeName, func(t *testing.T) {
			ad := AuthorizationDetail{Type: typeName}
			assert.NoError(t, ad.Validate())
		})
	}
}
