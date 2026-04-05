package domain

// RFC 8693 grant type URI for token exchange.
// https://www.rfc-editor.org/rfc/rfc8693#section-2.1
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// RFC 8693 token type URI constants used in subject_token_type, actor_token_type,
// and requested_token_type fields.
// https://www.rfc-editor.org/rfc/rfc8693#section-3
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeSAML1        = "urn:ietf:params:oauth:token-type:saml1"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

// ActorClaim represents the nested `act` (actor) claim in a JWT per RFC 8693 §4.1.
// It enables delegation chains where one identity acts on behalf of another.
// Nested Act fields support multi-hop delegation (A acts as B acts as C).
type ActorClaim struct {
	// Subject identifies the actor (the delegating principal).
	Subject string `json:"sub,omitempty"`
	// Issuer identifies the issuer that asserted the actor's identity.
	Issuer string `json:"iss,omitempty"`
	// Act is an optional nested actor for multi-hop delegation chains.
	Act *ActorClaim `json:"act,omitempty"`
}
