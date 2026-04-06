// Package saml implements the SAML Service Provider (SP) flow including
// metadata generation, AuthnRequest construction, response validation,
// attribute mapping, and JIT user provisioning.
package saml

import (
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"net/url"
)

// NameIDFormat constants for SAML NameID policies.
const (
	NameIDFormatPersistent    = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatEmailAddress  = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatUnspecified   = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatTransient     = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// Binding constants for SAML protocol bindings.
const (
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SPConfig holds the Service Provider configuration.
type SPConfig struct {
	// EntityID is the unique identifier for this SP (typically the metadata URL).
	EntityID string

	// ACSURL is the Assertion Consumer Service URL where the IdP posts SAML responses.
	ACSURL string

	// MetadataURL is the URL where SP metadata is served.
	MetadataURL string

	// Certificate is the SP's X.509 certificate for signature verification.
	// Optional: only needed if signing AuthnRequests.
	Certificate *x509.Certificate

	// NameIDFormat specifies which NameID format to request from the IdP.
	// Defaults to NameIDFormatPersistent if empty.
	NameIDFormat string

	// WantAssertionsSigned requires the IdP to sign assertions (recommended).
	WantAssertionsSigned bool
}

// spEntityDescriptor is the XML structure for SP metadata.
type spEntityDescriptor struct {
	XMLName  xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string            `xml:"entityID,attr"`
	SPSSODescriptor spSSODescriptor `xml:"SPSSODescriptor"`
}

// spSSODescriptor describes the SP's SSO capabilities.
type spSSODescriptor struct {
	XMLName                    xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	ProtocolSupportEnumeration string                     `xml:"protocolSupportEnumeration,attr"`
	AuthnRequestsSigned        bool                       `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool                       `xml:"WantAssertionsSigned,attr"`
	NameIDFormats              []nameIDFormat              `xml:"NameIDFormat"`
	AssertionConsumerServices  []assertionConsumerService  `xml:"AssertionConsumerService"`
}

// nameIDFormat is the XML element for NameID format declarations.
type nameIDFormat struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata NameIDFormat"`
	Value   string   `xml:",chardata"`
}

// assertionConsumerService is the XML element for ACS endpoint declarations.
type assertionConsumerService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
	Index    int      `xml:"index,attr"`
}

// GenerateMetadata produces the SP metadata XML document.
func GenerateMetadata(cfg SPConfig) ([]byte, error) {
	if cfg.EntityID == "" {
		return nil, fmt.Errorf("generate metadata: entity ID is required")
	}
	if cfg.ACSURL == "" {
		return nil, fmt.Errorf("generate metadata: ACS URL is required")
	}
	if _, err := url.Parse(cfg.ACSURL); err != nil {
		return nil, fmt.Errorf("generate metadata: invalid ACS URL: %w", err)
	}

	nidFormat := cfg.NameIDFormat
	if nidFormat == "" {
		nidFormat = NameIDFormatPersistent
	}

	desc := spEntityDescriptor{
		EntityID: cfg.EntityID,
		SPSSODescriptor: spSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			AuthnRequestsSigned:        cfg.Certificate != nil,
			WantAssertionsSigned:       cfg.WantAssertionsSigned,
			NameIDFormats: []nameIDFormat{
				{Value: nidFormat},
			},
			AssertionConsumerServices: []assertionConsumerService{
				{
					Binding:  BindingHTTPPost,
					Location: cfg.ACSURL,
					Index:    0,
				},
			},
		},
	}

	data, err := xml.MarshalIndent(desc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("generate metadata: marshal XML: %w", err)
	}

	// Prepend XML declaration.
	return append([]byte(xml.Header), data...), nil
}
