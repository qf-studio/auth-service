package e2e

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	dockerclient "github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// TestNegative_RevokedAccessTokenRejected (GH-494) proves that once an
// access token has been revoked via POST /auth/revoke, reusing it on a
// protected route is rejected — exercising the real Redis-backed blocklist
// path in internal/token.Service.Revoke/IsRevoked (internal/token/service.go),
// which, unlike the review-003 wave-2 gaps elsewhere in this package, is
// genuinely wired end to end today.
func TestNegative_RevokedAccessTokenRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	email := newE2EEmail("revoked-token")
	registerUser(t, suite.HTTPClient, email, fakeUserPassword)
	login := loginUser(t, suite.HTTPClient, email, fakeUserPassword)
	require.NotEmpty(t, login.AccessToken)

	status, _ := doAuthedJSON(t, suite.HTTPClient, http.MethodGet, suite.PublicBaseURL+"/auth/me", login.AccessToken, nil, nil)
	require.Equal(t, http.StatusOK, status, "access token must work before revocation")

	revokeStatus, _ := postJSON(t, suite.HTTPClient, suite.PublicBaseURL+"/auth/revoke", map[string]string{
		"token": login.AccessToken,
	}, nil)
	require.Equal(t, http.StatusOK, revokeStatus, "revoke status")

	status, _ = doAuthedJSON(t, suite.HTTPClient, http.MethodGet, suite.PublicBaseURL+"/auth/me", login.AccessToken, nil, nil)
	require.Equal(t, http.StatusUnauthorized, status, "revoked access token reuse must be rejected")
}

// TestNegative_ExpiredAccessTokenRejected (GH-494) proves an access token is
// rejected once it passes its TTL. The shared suite runs with the default
// 15m ACCESS_TOKEN_TTL, far too long to wait out in a test, so this starts a
// second SUT container (same Postgres/Redis, via startSecondarySUT) with a
// seconds-level override so the expiry can actually be observed.
func TestNegative_ExpiredAccessTokenRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sut, teardown, err := startSecondarySUT(ctx, suite, map[string]string{
		"ACCESS_TOKEN_TTL": "2s",
	})
	require.NoError(t, err, "start secondary SUT with a short access-token TTL")
	defer teardown()

	email := newE2EEmail("expired-token")
	var registered registerResponse
	status, _ := postJSON(t, sut.HTTPClient, sut.PublicBaseURL+"/auth/register", map[string]string{
		"email":    email,
		"password": fakeUserPassword,
		"name":     "E2E Expired Token User",
	}, &registered)
	require.Equal(t, http.StatusCreated, status, "register status")

	var login authResponse
	status, _ = postJSON(t, sut.HTTPClient, sut.PublicBaseURL+"/auth/login", map[string]string{
		"email":    email,
		"password": fakeUserPassword,
	}, &login)
	require.Equal(t, http.StatusOK, status, "login status")
	require.NotEmpty(t, login.AccessToken)

	status, _ = doAuthedJSON(t, sut.HTTPClient, http.MethodGet, sut.PublicBaseURL+"/auth/me", login.AccessToken, nil, nil)
	require.Equal(t, http.StatusOK, status, "access token must work before it expires")

	time.Sleep(3 * time.Second) // > the 2s ACCESS_TOKEN_TTL override above

	status, _ = doAuthedJSON(t, sut.HTTPClient, http.MethodGet, sut.PublicBaseURL+"/auth/me", login.AccessToken, nil, nil)
	require.Equal(t, http.StatusUnauthorized, status, "expired access token must be rejected")
}

// TestNegative_LoginRateLimitReturns429 (GH-494) proves the per-IP rate
// limiter (internal/middleware.RateLimiter, wired globally on the public
// router — see internal/api/router.go's "if mw.RateLimit != nil" branch)
// actually rejects with 429 plus a Retry-After header once its bucket is
// exhausted. The shared suite runs with the default RATE_LIMIT_RPS=50 /
// RATE_LIMIT_BURST=100, too generous to exhaust reliably in a fast test, so
// this starts a second SUT container with a tight override.
func TestNegative_LoginRateLimitReturns429(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sut, teardown, err := startSecondarySUT(ctx, suite, map[string]string{
		"RATE_LIMIT_RPS":   "1",
		"RATE_LIMIT_BURST": "1",
	})
	require.NoError(t, err, "start secondary SUT with a tight rate limit")
	defer teardown()

	loginBody := map[string]string{
		"email":    newE2EEmail("rate-limit"),
		"password": "wrong-password-doesnt-matter", //nolint:gosec // fake, test-only
	}

	var sawTooManyRequests bool
	var retryAfter string
	for i := 0; i < 5; i++ {
		status, headers := postJSON(t, sut.HTTPClient, sut.PublicBaseURL+"/auth/login", loginBody, nil)
		if status == http.StatusTooManyRequests {
			sawTooManyRequests = true
			retryAfter = headers.Get("Retry-After")
			break
		}
	}

	require.True(t, sawTooManyRequests, "expected at least one 429 from the exhausted per-IP rate limit bucket")
	require.NotEmpty(t, retryAfter, "429 response must carry a Retry-After header")
}

// TestNegative_ReadinessFailsWhenRedisPausedButLivenessDoesNot (GH-494)
// proves /liveness and /readiness (internal/health, wired in
// internal/api/router.go) actually have different failure semantics: pausing
// (not stopping) the shared suite's Redis container simulates a dependency
// outage without tearing anything down, and readiness — which runs
// health.RedisChecker — must flip to 503 while liveness, which performs no
// dependency checks at all, must keep answering 200.
func TestNegative_ReadinessFailsWhenRedisPausedButLivenessDoesNot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	provider, err := testcontainers.NewDockerProvider()
	require.NoError(t, err, "docker provider")
	defer func() { _ = provider.Close() }()

	dockerCli := provider.Client()
	redisID := suite.redisContainer.GetContainerID()

	require.Equal(t, http.StatusOK, probeStatus(t, suite.PublicBaseURL+"/readiness"),
		"sanity: readiness must be healthy before pausing redis")

	_, err = dockerCli.ContainerPause(context.Background(), redisID, dockerclient.ContainerPauseOptions{})
	require.NoError(t, err, "pause redis container")

	// Always restore Redis and wait for readiness to recover, even if an
	// assertion below fails, so later tests in this package don't inherit a
	// broken shared suite.
	t.Cleanup(func() {
		unpauseCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = dockerCli.ContainerUnpause(unpauseCtx, redisID, dockerclient.ContainerUnpauseOptions{})
		require.Eventually(t, func() bool {
			return probeStatus(t, suite.PublicBaseURL+"/readiness") == http.StatusOK
		}, 15*time.Second, 500*time.Millisecond, "readiness did not recover after unpausing redis")
	})

	require.Eventually(t, func() bool {
		return probeStatus(t, suite.PublicBaseURL+"/readiness") == http.StatusServiceUnavailable
	}, 15*time.Second, 500*time.Millisecond, "readiness must report unhealthy while redis is paused")

	require.Equal(t, http.StatusOK, probeStatus(t, suite.PublicBaseURL+"/liveness"),
		"liveness must stay healthy even while a dependency (redis) is down")
}

// probeStatus issues a bodiless GET against url and returns its status code.
func probeStatus(t *testing.T, url string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	require.NoError(t, err)

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "GET %s", url)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// prometheusMetricLinePattern matches a single Prometheus text-exposition
// sample line: a metric name (optionally with a {label="value",...} block),
// whitespace, and a numeric value. Used by
// TestNegative_PrometheusMetricsParseAsPrometheusFormat below to check every
// non-comment line of GET /admin/metrics/prometheus's output looks like a
// real sample rather than, say, an accidentally-JSON-shaped body.
var prometheusMetricLinePattern = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})?\s+-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// TestNegative_PrometheusMetricsParseAsPrometheusFormat (GH-494) proves
// GET /admin/metrics/prometheus (internal/api/admin_router.go, backed by
// internal/metrics.Collector.PrometheusExport) actually emits the Prometheus
// text exposition format — HELP/TYPE annotations plus name/value sample
// lines — rather than merely returning 200 with an arbitrary text/plain
// body. There is no prometheus client/expfmt dependency in this module, so
// this checks the format directly against the documented exposition grammar
// instead of pulling one in just for this test.
func TestNegative_PrometheusMetricsParseAsPrometheusFormat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	req, err := http.NewRequest(http.MethodGet, suite.AdminBaseURL+"/admin/metrics/prometheus", http.NoBody)
	require.NoError(t, err)

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "GET /admin/metrics/prometheus")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var sawHelp, sawType, sawSample bool
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "# HELP "):
			sawHelp = true
			require.Len(t, strings.SplitN(strings.TrimPrefix(line, "# HELP "), " ", 2), 2,
				"malformed HELP line: %q", line)
		case strings.HasPrefix(line, "# TYPE "):
			sawType = true
			fields := strings.Fields(strings.TrimPrefix(line, "# TYPE "))
			require.Len(t, fields, 2, "malformed TYPE line: %q", line)
			require.Contains(t, []string{"counter", "gauge", "histogram", "summary", "untyped"}, fields[1],
				"unrecognized metric type in line %q", line)
		default:
			sawSample = true
			require.Regexp(t, prometheusMetricLinePattern, line,
				"line does not look like a prometheus exposition sample: %q", line)
		}
	}

	require.True(t, sawHelp, "expected at least one # HELP line in prometheus output")
	require.True(t, sawType, "expected at least one # TYPE line in prometheus output")
	require.True(t, sawSample, "expected at least one metric sample line in prometheus output")
}
