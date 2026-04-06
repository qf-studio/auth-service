package saml

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/url"
	"sync"
	"time"
)

// IdPConfig holds Identity Provider configuration.
type IdPConfig struct {
	// EntityID is the IdP's unique entity identifier.
	EntityID string

	// SSOURL is the IdP's single sign-on endpoint.
	SSOURL string

	// SSOBinding is the protocol binding for SSO (default: HTTP-Redirect).
	SSOBinding string

	// Certificate is the IdP's X.509 certificate in PEM format for signature verification.
	CertificatePEM string
}

// authnRequest is the XML structure for a SAML AuthnRequest.
type authnRequest struct {
	XMLName                 xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                      string   `xml:"ID,attr"`
	Version                 string   `xml:"Version,attr"`
	IssueInstant            string   `xml:"IssueInstant,attr"`
	Destination             string   `xml:"Destination,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding         string   `xml:"ProtocolBinding,attr"`
	Issuer                  issuer   `xml:"Issuer"`
	NameIDPolicy            *nameIDPolicy `xml:"NameIDPolicy,omitempty"`
}

// issuer is the SAML Issuer element.
type issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// nameIDPolicy specifies the NameID format requested.
type nameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr"`
	AllowCreate bool     `xml:"AllowCreate,attr"`
}

// RequestTracker tracks pending AuthnRequest IDs to validate InResponseTo fields.
type RequestTracker struct {
	mu       sync.RWMutex
	pending  map[string]time.Time
	ttl      time.Duration
}

// NewRequestTracker creates a request tracker with the given TTL for pending requests.
func NewRequestTracker(ttl time.Duration) *RequestTracker {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &RequestTracker{
		pending: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// Track stores a request ID with its creation time.
func (rt *RequestTracker) Track(requestID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.pending[requestID] = time.Now()
}

// Consume validates and removes a request ID. Returns true if the ID was valid and not expired.
func (rt *RequestTracker) Consume(requestID string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	created, ok := rt.pending[requestID]
	if !ok {
		return false
	}
	delete(rt.pending, requestID)

	return time.Since(created) < rt.ttl
}

// Cleanup removes expired entries. Should be called periodically.
func (rt *RequestTracker) Cleanup() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	for id, created := range rt.pending {
		if now.Sub(created) >= rt.ttl {
			delete(rt.pending, id)
		}
	}
}

// BuildAuthnRequest constructs a SAML AuthnRequest and returns the redirect URL.
func BuildAuthnRequest(sp SPConfig, idp IdPConfig) (redirectURL string, requestID string, err error) {
	if idp.SSOURL == "" {
		return "", "", fmt.Errorf("build authn request: IdP SSO URL is required")
	}
	if sp.EntityID == "" {
		return "", "", fmt.Errorf("build authn request: SP entity ID is required")
	}
	if sp.ACSURL == "" {
		return "", "", fmt.Errorf("build authn request: SP ACS URL is required")
	}

	requestID, err = generateRequestID()
	if err != nil {
		return "", "", fmt.Errorf("build authn request: %w", err)
	}

	nidFormat := sp.NameIDFormat
	if nidFormat == "" {
		nidFormat = NameIDFormatPersistent
	}

	req := authnRequest{
		ID:                      requestID,
		Version:                 "2.0",
		IssueInstant:            time.Now().UTC().Format(time.RFC3339),
		Destination:             idp.SSOURL,
		AssertionConsumerServiceURL: sp.ACSURL,
		ProtocolBinding:         BindingHTTPPost,
		Issuer:                  issuer{Value: sp.EntityID},
		NameIDPolicy: &nameIDPolicy{
			Format:      nidFormat,
			AllowCreate: true,
		},
	}

	data, err := xml.Marshal(req)
	if err != nil {
		return "", "", fmt.Errorf("build authn request: marshal XML: %w", err)
	}

	encoded, err := deflateAndEncode(data)
	if err != nil {
		return "", "", fmt.Errorf("build authn request: deflate: %w", err)
	}

	u, err := url.Parse(idp.SSOURL)
	if err != nil {
		return "", "", fmt.Errorf("build authn request: parse SSO URL: %w", err)
	}

	q := u.Query()
	q.Set("SAMLRequest", encoded)
	u.RawQuery = q.Encode()

	return u.String(), requestID, nil
}

// generateRequestID produces a SAML-compliant request ID (must start with a letter or underscore).
func generateRequestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return "_" + hex.EncodeToString(b), nil
}
