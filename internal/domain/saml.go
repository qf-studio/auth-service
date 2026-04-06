package domain

import "time"

// SAMLIdentity represents a linked SAML identity provider account for a user.
type SAMLIdentity struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	IdPEntityID   string    `json:"idp_entity_id"`
	NameID        string    `json:"name_id"`
	Email         string    `json:"email,omitempty"`
	SessionIndex  string    `json:"session_index,omitempty"`
	Attributes    map[string][]string `json:"attributes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}
