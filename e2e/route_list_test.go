package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// ginDefault404Body is gin's literal NoRoute response body
// (github.com/gin-gonic/gin: default404Body = []byte("404 page not found")),
// written verbatim whenever no route matches a request at all — including a
// method that doesn't match any registered route, since neither router here
// sets HandleMethodNotAllowed. Every app-level "not found" instead goes
// through domain.RespondWithError, which always writes a JSON body. That
// difference is exactly what routeIsMounted below relies on: a route that
// legitimately looks up a placeholder ID and finds nothing still answers
// with JSON (mounted, business logic ran); a route whose whole group
// silently failed to mount (the dominant review-003 failure class — a
// nil-guarded group, e.g. "if mfaH != nil", never becoming true) falls
// through to gin's NoRoute handler and answers with this exact text.
const ginDefault404Body = "404 page not found"

// placeholderID substitutes for every path parameter in goldenRoutes below
// (:id, :provider, :delivery_id, ...). It is never expected to resolve to a
// real resource — the point of this test is only that the route mounts,
// not that the specific resource exists (see routeIsMounted).
const placeholderID = "gh494-route-check"

// routeCheck is one (method, path) entry in the golden route table.
type routeCheck struct {
	method string
	path   string // may contain ":param" segments, substituted with placeholderID
}

// publicGoldenRoutes is every route NewPublicRouter (internal/api/router.go)
// registers given the service wiring cmd/server/main.go actually constructs
// today: Session, MFA, OAuth, and OIDC services are all non-nil there, so
// those conditional route groups in router.go mount. Broker and SAML are
// NOT wired — main.go declares "var brokerTokenSvc api.BrokerTokenService"
// and "var samlSvc api.SAMLService" as bare nil interface values with a
// "registered in a subsequent issue" comment, so router.go's
// "if svc.Broker != nil" / "if svc.SAML != nil" guards are always false —
// so /auth/broker/token and /auth/saml/{metadata,login,acs} do not exist on
// the real server today and are deliberately absent from this table. When
// one of those ships, add its routes here in the same PR. If a future
// main.go stops wiring one of the currently-mounted services, the
// corresponding group silently disappears from the live router exactly as
// review-003 warned about — this table must be updated in the same PR that
// changes that wiring, or this test starts failing (intentionally).
var publicGoldenRoutes = []routeCheck{
	{http.MethodGet, "/health"},
	{http.MethodGet, "/liveness"},
	{http.MethodGet, "/readiness"},
	{http.MethodGet, "/.well-known/jwks.json"},
	{http.MethodGet, "/.well-known/openid-configuration"},
	{http.MethodGet, "/oauth/authorize"},
	{http.MethodPost, "/oauth/token"},
	{http.MethodPost, "/auth/register"},
	{http.MethodPost, "/auth/login"},
	{http.MethodPost, "/auth/token"},
	{http.MethodPost, "/auth/revoke"},
	{http.MethodPost, "/auth/verify-email"},
	{http.MethodPost, "/auth/password/reset"},
	{http.MethodPost, "/auth/password/reset/confirm"},
	{http.MethodPost, "/auth/mfa/verify"},
	{http.MethodGet, "/auth/oauth/:provider"},
	{http.MethodGet, "/auth/oauth/:provider/callback"},
	{http.MethodGet, "/auth/me"},
	{http.MethodPut, "/auth/me/password"},
	{http.MethodPost, "/auth/logout"},
	{http.MethodPost, "/auth/logout/all"},
	{http.MethodGet, "/auth/sessions"},
	{http.MethodDelete, "/auth/sessions/:id"},
	{http.MethodDelete, "/auth/sessions"},
	{http.MethodPost, "/auth/mfa/setup"},
	{http.MethodPost, "/auth/mfa/confirm"},
	{http.MethodPost, "/auth/mfa/disable"},
	{http.MethodGet, "/auth/mfa/status"},
	{http.MethodGet, "/auth/me/oauth"},
	{http.MethodDelete, "/auth/me/oauth/:provider"},
	{http.MethodGet, "/userinfo"},
}

// adminGoldenRoutes is every route NewAdminRouter (internal/api/admin_router.go)
// registers given cmd/server/main.go's actual AdminServices wiring. Users,
// Clients, Tokens, APIKeys, user-MFA, Webhooks, Consent, and ClientApproval
// are all wired there, so those groups mount. Brokers, SAML, and Tenants
// are NOT wired (cmd/server/main.go sets adminBrokerSvc/adminSAMLSvc as
// bare nil interface values with a "registered in a subsequent issue"
// comment, and never sets AdminServices.Tenants at all) — so
// /admin/credentials, /admin/saml/idps, and /admin/tenants do not exist on
// the real server today and are deliberately absent from this table. When
// one of those three ships, add its routes here in the same PR.
var adminGoldenRoutes = []routeCheck{
	{http.MethodGet, "/health"},
	{http.MethodGet, "/admin/metrics"},
	{http.MethodGet, "/admin/metrics/prometheus"},
	{http.MethodGet, "/admin/users"},
	{http.MethodGet, "/admin/users/:id"},
	{http.MethodPost, "/admin/users"},
	{http.MethodPatch, "/admin/users/:id"},
	{http.MethodDelete, "/admin/users/:id"},
	{http.MethodPost, "/admin/users/:id/lock"},
	{http.MethodPost, "/admin/users/:id/unlock"},
	{http.MethodGet, "/admin/users/:id/activity"},
	{http.MethodPost, "/admin/users/bulk/lock"},
	{http.MethodPost, "/admin/users/bulk/unlock"},
	{http.MethodPost, "/admin/users/bulk/suspend"},
	{http.MethodPost, "/admin/users/bulk/assign-role"},
	{http.MethodGet, "/admin/users/:id/mfa"},
	{http.MethodDelete, "/admin/users/:id/mfa"},
	{http.MethodGet, "/admin/clients"},
	{http.MethodGet, "/admin/clients/:id"},
	{http.MethodPost, "/admin/clients"},
	{http.MethodPatch, "/admin/clients/:id"},
	{http.MethodDelete, "/admin/clients/:id"},
	{http.MethodPost, "/admin/clients/:id/rotate-secret"},
	{http.MethodGet, "/admin/apikeys"},
	{http.MethodGet, "/admin/apikeys/:id"},
	{http.MethodPost, "/admin/apikeys"},
	{http.MethodPatch, "/admin/apikeys/:id"},
	{http.MethodDelete, "/admin/apikeys/:id"},
	{http.MethodPost, "/admin/apikeys/:id/rotate"},
	{http.MethodGet, "/admin/webhooks"},
	{http.MethodGet, "/admin/webhooks/:id"},
	{http.MethodPost, "/admin/webhooks"},
	{http.MethodPatch, "/admin/webhooks/:id"},
	{http.MethodDelete, "/admin/webhooks/:id"},
	{http.MethodGet, "/admin/webhooks/:id/deliveries"},
	{http.MethodPost, "/admin/webhooks/:id/deliveries/:delivery_id/retry"},
	{http.MethodPost, "/admin/webhooks/:id/test"},
	{http.MethodPost, "/admin/tokens/introspect"},
	{http.MethodGet, "/admin/oauth/auth/requests/login"},
	{http.MethodPut, "/admin/oauth/auth/requests/login"},
	{http.MethodGet, "/admin/oauth/auth/requests/consent"},
	{http.MethodPut, "/admin/oauth/auth/requests/consent"},
	{http.MethodGet, "/admin/clients/:id/approve"},
}

// TestGoldenRouteList_PublicRouter and TestGoldenRouteList_AdminRouter
// (GH-494) black-box assert every entry in the golden route tables above
// mounts on the real running SUT: a route disappearing (its whole group
// failing a nil-guard in router.go/admin_router.go, or the table itself
// going stale after a main.go wiring change) fails with a diff naming
// exactly which (method, path) pairs vanished. See ginDefault404Body for
// why "mounted" is checked via response body rather than status code alone.
func TestGoldenRouteList_PublicRouter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}
	assertRoutesMounted(t, suite.PublicBaseURL, publicGoldenRoutes)
}

func TestGoldenRouteList_AdminRouter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}
	assertRoutesMounted(t, suite.AdminBaseURL, adminGoldenRoutes)
}

// assertRoutesMounted fires every route in routes against baseURL and
// collects every one that answers with gin's literal NoRoute body, failing
// the test once with a single named diff listing all of them (rather than
// one failure per route) so a whole-group unmount is immediately legible.
func assertRoutesMounted(t *testing.T, baseURL string, routes []routeCheck) {
	t.Helper()

	var unmounted []string
	for _, rt := range routes {
		path := strings.ReplaceAll(rt.path, ":id", placeholderID)
		path = strings.ReplaceAll(path, ":provider", placeholderID)
		path = strings.ReplaceAll(path, ":delivery_id", placeholderID)

		req, err := http.NewRequest(rt.method, baseURL+path, http.NoBody)
		require.NoError(t, err)

		resp, err := suite.HTTPClient.Do(req)
		require.NoError(t, err, "%s %s", rt.method, path)

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err, "%s %s: read body", rt.method, path)

		if resp.StatusCode == http.StatusNotFound && strings.TrimSpace(string(body)) == ginDefault404Body {
			unmounted = append(unmounted, rt.method+" "+rt.path)
		}
	}

	require.Empty(t, unmounted, "routes not mounted on %s (gin NoRoute, not app-level 404):\n%s",
		baseURL, strings.Join(unmounted, "\n"))
}
