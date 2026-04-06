package domain

import "time"

// SAMLIdPConfig represents a SAML Identity Provider configuration.
type SAMLIdPConfig struct {
	ID                string
	TenantID          string
	EntityID          string
	MetadataURL       string
	MetadataXML       string
	SSOURL            string
	SLOURL            string
	Certificate       string
	Name              string
	AttributeMappings map[string]string
	Enabled           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// SAMLAccount links a SAML NameID to an internal user account.
type SAMLAccount struct {
	ID               string
	TenantID         string
	UserID           string
	IdPID            string
	NameID           string
	SessionIndex     string
	CachedAttributes map[string]string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// SAMLAttributeMapping defines how SAML assertion attributes map to internal user fields.
type SAMLAttributeMapping struct {
	SAMLAttribute string `json:"saml_attribute"`
	UserField     string `json:"user_field"`
}

// --- Admin request/response DTOs ---

// CreateSAMLIdPRequest is the admin DTO for registering a new SAML IdP.
type CreateSAMLIdPRequest struct {
	EntityID          string            `json:"entity_id" binding:"required"`
	MetadataURL       string            `json:"metadata_url,omitempty"`
	MetadataXML       string            `json:"metadata_xml,omitempty"`
	SSOURL            string            `json:"sso_url" binding:"required"`
	SLOURL            string            `json:"slo_url,omitempty"`
	Certificate       string            `json:"certificate" binding:"required"`
	Name              string            `json:"name" binding:"required"`
	AttributeMappings map[string]string `json:"attribute_mappings,omitempty"`
	Enabled           *bool             `json:"enabled,omitempty"`
}

// UpdateSAMLIdPRequest is the admin DTO for updating an existing SAML IdP.
type UpdateSAMLIdPRequest struct {
	MetadataURL       *string            `json:"metadata_url,omitempty"`
	MetadataXML       *string            `json:"metadata_xml,omitempty"`
	SSOURL            *string            `json:"sso_url,omitempty"`
	SLOURL            *string            `json:"slo_url,omitempty"`
	Certificate       *string            `json:"certificate,omitempty"`
	Name              *string            `json:"name,omitempty"`
	AttributeMappings *map[string]string `json:"attribute_mappings,omitempty"`
	Enabled           *bool              `json:"enabled,omitempty"`
}

// SAMLIdPResponse is the admin DTO returned when reading an IdP configuration.
type SAMLIdPResponse struct {
	ID                string            `json:"id"`
	EntityID          string            `json:"entity_id"`
	MetadataURL       string            `json:"metadata_url,omitempty"`
	SSOURL            string            `json:"sso_url"`
	SLOURL            string            `json:"slo_url,omitempty"`
	Name              string            `json:"name"`
	AttributeMappings map[string]string `json:"attribute_mappings,omitempty"`
	Enabled           bool              `json:"enabled"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// SAMLAccountResponse is the admin DTO returned when reading a SAML account link.
type SAMLAccountResponse struct {
	ID               string            `json:"id"`
	UserID           string            `json:"user_id"`
	IdPID            string            `json:"idp_id"`
	NameID           string            `json:"name_id"`
	CachedAttributes map[string]string `json:"cached_attributes,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}
