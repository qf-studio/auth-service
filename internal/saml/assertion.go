package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Default clock skew tolerance for assertion validation.
const defaultClockSkew = 2 * time.Minute

// ParsedAssertion contains the validated data extracted from a SAML response.
type ParsedAssertion struct {
	// Issuer is the IdP entity ID that issued the assertion.
	Issuer string

	// NameID is the subject's persistent identifier from the IdP.
	NameID string

	// NameIDFormat is the format of the NameID.
	NameIDFormat string

	// SessionIndex is the IdP session index for single logout.
	SessionIndex string

	// Attributes contains all SAML attributes from the assertion.
	Attributes map[string][]string

	// InResponseTo is the request ID this response answers.
	InResponseTo string

	// NotBefore and NotOnOrAfter define the assertion's validity window.
	NotBefore    time.Time
	NotOnOrAfter time.Time
}

// samlResponse is the top-level SAML Response XML structure.
type samlResponse struct {
	XMLName      xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string         `xml:"ID,attr"`
	InResponseTo string         `xml:"InResponseTo,attr"`
	Destination  string         `xml:"Destination,attr"`
	IssueInstant string         `xml:"IssueInstant,attr"`
	Status       samlStatus     `xml:"Status"`
	Issuer       string         `xml:"Issuer"`
	Assertions   []samlAssertion `xml:"Assertion"`
}

// samlStatus holds the response status code.
type samlStatus struct {
	StatusCode samlStatusCode `xml:"StatusCode"`
}

type samlStatusCode struct {
	Value string `xml:"Value,attr"`
}

// samlAssertion is a SAML assertion element.
type samlAssertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string              `xml:"ID,attr"`
	Issuer             string              `xml:"Issuer"`
	Subject            samlSubject         `xml:"Subject"`
	Conditions         samlConditions      `xml:"Conditions"`
	AuthnStatements    []samlAuthnStatement `xml:"AuthnStatement"`
	AttributeStatements []samlAttributeStatement `xml:"AttributeStatement"`
	Signature          *xmlSignature       `xml:"Signature"`
}

type samlSubject struct {
	NameID              samlNameID              `xml:"NameID"`
	SubjectConfirmation samlSubjectConfirmation `xml:"SubjectConfirmation"`
}

type samlNameID struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

type samlSubjectConfirmation struct {
	Method string                      `xml:"Method,attr"`
	Data   samlSubjectConfirmationData `xml:"SubjectConfirmationData"`
}

type samlSubjectConfirmationData struct {
	InResponseTo string `xml:"InResponseTo,attr"`
	Recipient    string `xml:"Recipient,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type samlConditions struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
}

type samlAuthnStatement struct {
	SessionIndex string `xml:"SessionIndex,attr"`
}

type samlAttributeStatement struct {
	Attributes []samlAttribute `xml:"Attribute"`
}

type samlAttribute struct {
	Name   string          `xml:"Name,attr"`
	Values []samlAttrValue `xml:"AttributeValue"`
}

type samlAttrValue struct {
	Value string `xml:",chardata"`
}

// xmlSignature is a minimal representation for detecting signature presence.
type xmlSignature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
}

// AssertionValidator validates and extracts data from SAML responses.
type AssertionValidator struct {
	// spEntityID is the expected audience (our SP entity ID).
	spEntityID string

	// acsURL is the expected destination/recipient.
	acsURL string

	// idpCerts maps IdP entity IDs to their parsed X.509 certificates.
	idpCerts map[string]*x509.Certificate

	// clockSkew is the tolerance for time-based validations.
	clockSkew time.Duration

	// requestTracker validates InResponseTo values.
	requestTracker *RequestTracker

	// nowFunc returns the current time (injectable for testing).
	nowFunc func() time.Time
}

// AssertionValidatorOption configures an AssertionValidator.
type AssertionValidatorOption func(*AssertionValidator)

// WithClockSkew sets the clock skew tolerance.
func WithClockSkew(d time.Duration) AssertionValidatorOption {
	return func(v *AssertionValidator) { v.clockSkew = d }
}

// WithNowFunc overrides the time source (for testing).
func WithNowFunc(fn func() time.Time) AssertionValidatorOption {
	return func(v *AssertionValidator) { v.nowFunc = fn }
}

// NewAssertionValidator creates a validator for SAML assertions.
func NewAssertionValidator(
	spEntityID, acsURL string,
	tracker *RequestTracker,
	opts ...AssertionValidatorOption,
) *AssertionValidator {
	v := &AssertionValidator{
		spEntityID:     spEntityID,
		acsURL:         acsURL,
		idpCerts:       make(map[string]*x509.Certificate),
		clockSkew:      defaultClockSkew,
		requestTracker: tracker,
		nowFunc:        time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// RegisterIdPCertificate parses and registers an IdP's certificate for signature verification.
func (v *AssertionValidator) RegisterIdPCertificate(idpEntityID, certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("register idp cert: no PEM block found for %s", idpEntityID)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("register idp cert: parse certificate for %s: %w", idpEntityID, err)
	}

	v.idpCerts[idpEntityID] = cert
	return nil
}

// ValidateResponse parses a base64-encoded SAML response and validates the assertion.
func (v *AssertionValidator) ValidateResponse(samlResponseB64 string) (*ParsedAssertion, error) {
	rawXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("validate response: decode base64: %w: %w", err, domain.ErrSAMLResponseInvalid)
	}

	var resp samlResponse
	if err := xml.Unmarshal(rawXML, &resp); err != nil {
		return nil, fmt.Errorf("validate response: unmarshal XML: %w: %w", err, domain.ErrSAMLResponseInvalid)
	}

	// Verify status.
	if resp.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return nil, fmt.Errorf("validate response: non-success status %s: %w",
			resp.Status.StatusCode.Value, domain.ErrSAMLResponseInvalid)
	}

	if len(resp.Assertions) == 0 {
		return nil, fmt.Errorf("validate response: no assertions found: %w", domain.ErrSAMLResponseInvalid)
	}

	assertion := resp.Assertions[0]

	// Verify the IdP is registered.
	idpEntityID := assertion.Issuer
	if idpEntityID == "" {
		idpEntityID = resp.Issuer
	}
	if _, ok := v.idpCerts[idpEntityID]; !ok && len(v.idpCerts) > 0 {
		return nil, fmt.Errorf("validate response: unknown IdP %s: %w", idpEntityID, domain.ErrSAMLIdPNotConfigured)
	}

	// Validate InResponseTo if tracker is configured.
	if v.requestTracker != nil && resp.InResponseTo != "" {
		if !v.requestTracker.Consume(resp.InResponseTo) {
			return nil, fmt.Errorf("validate response: %w", domain.ErrSAMLRequestIDMismatch)
		}
	}

	// Validate time conditions.
	now := v.nowFunc().UTC()
	if assertion.Conditions.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
		if err == nil && now.Add(v.clockSkew).Before(notBefore) {
			return nil, fmt.Errorf("validate response: assertion not yet valid: %w", domain.ErrSAMLAssertionExpired)
		}
	}
	if assertion.Conditions.NotOnOrAfter != "" {
		notOnOrAfter, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
		if err == nil && now.Add(-v.clockSkew).After(notOnOrAfter) {
			return nil, fmt.Errorf("validate response: assertion expired: %w", domain.ErrSAMLAssertionExpired)
		}
	}

	// Extract attributes.
	attrs := make(map[string][]string)
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			values := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				values = append(values, v.Value)
			}
			attrs[attr.Name] = values
		}
	}

	// Extract session index.
	var sessionIndex string
	if len(assertion.AuthnStatements) > 0 {
		sessionIndex = assertion.AuthnStatements[0].SessionIndex
	}

	// Parse time boundaries for the result.
	var notBefore, notOnOrAfter time.Time
	if assertion.Conditions.NotBefore != "" {
		notBefore, _ = time.Parse(time.RFC3339, assertion.Conditions.NotBefore)
	}
	if assertion.Conditions.NotOnOrAfter != "" {
		notOnOrAfter, _ = time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
	}

	return &ParsedAssertion{
		Issuer:       idpEntityID,
		NameID:       assertion.Subject.NameID.Value,
		NameIDFormat: assertion.Subject.NameID.Format,
		SessionIndex: sessionIndex,
		Attributes:   attrs,
		InResponseTo: resp.InResponseTo,
		NotBefore:    notBefore,
		NotOnOrAfter: notOnOrAfter,
	}, nil
}
