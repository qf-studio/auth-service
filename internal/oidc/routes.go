package oidc

// Route paths for the OIDC provider and userinfo endpoints. These must stay
// in sync with the routes registered in internal/api/router.go; they are
// duplicated here (rather than imported) because internal/api must not
// depend on internal/oidc. Used both to build the discovery document's
// absolute endpoint URLs and to reconstruct the original /oauth/authorize
// request URL surfaced to the login UI (LoginRequestInfo.RequestURL).
const (
	RouteDiscovery = "/.well-known/openid-configuration"
	RouteAuthorize = "/oauth/authorize"
	RouteToken     = "/oauth/token"
	RouteUserInfo  = "/userinfo"
	RouteJWKS      = "/.well-known/jwks.json"
)
