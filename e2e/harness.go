// Package e2e boots the real auth-service Docker image (not a hand-wired
// mock) against real Postgres and Redis testcontainers, then exercises
// golden-path flows over plain HTTP. This is the harness foundation
// (GH-493 / issue A1); flows beyond registration/login/me/refresh/logout are
// added by follow-up issues (A2-A4) on top of the Env type returned here.
//
// Every test in this package must guard itself with testing.Short() (no
// build tags) so `go test -short ./...` passes without a Docker daemon.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/qf-studio/auth-service/e2e/mocks"
)

const (
	postgresImage = "postgres:16-alpine"
	redisImage    = "redis:7.4-alpine"

	postgresAlias = "postgres"
	redisAlias    = "redis"

	sutPublicPort = "4000/tcp"
	sutAdminPort  = "4001/tcp"
	sutGRPCPort   = "4002/tcp"

	// containerKeyPath is where the generated ES256 signing key is mounted
	// inside the SUT container.
	containerKeyPath = "/tmp/e2e-jwt-private.pem"

	readinessTimeout      = 90 * time.Second
	readinessPollEvery    = 500 * time.Millisecond
	migrationExitTimeout  = 60 * time.Second
	containerStartTimeout = 60 * time.Second
)

// Env is the small suite API that follow-up issues (A2-A4) add golden-path
// flows onto. It intentionally exposes nothing about how the containers are
// wired so harness internals (network, image resolution, key generation)
// can change without touching flow tests.
type Env struct {
	PublicBaseURL string // e.g. http://localhost:32771
	AdminBaseURL  string
	GRPCAddr      string // host:port
	HTTPClient    *http.Client

	// EmailSink captures every message the SUT sends via the email-service
	// API (EMAIL_ENABLED=true, EMAIL_SERVICE_URL wired at it over
	// testcontainers host-port access), so email-dependent flows
	// (verify-email, password reset) can pull the link/token out instead of
	// needing a real mail transport.
	EmailSink *mocks.EmailSinkMock

	// HIBP is the fake Pwned Passwords range endpoint the SUT's HIBP client
	// is pointed at (HIBP_API_URL). No golden-path flow drives it today —
	// internal/auth.Service never calls the breach checker yet
	// ("HIBP never called", tracked as a review-003 wave-2 gap — see
	// DEVELOPMENT-README Current Focus) — but the env wiring is already in
	// place so a future fix needs no harness changes.
	HIBP *mocks.HIBPMock
}

// suiteResources holds everything setupSuite starts, so teardownSuite can
// release it in reverse order. It is unexported: flow tests only ever see
// the Env returned alongside it.
type suiteResources struct {
	sut       testcontainers.Container
	postgres  testcontainers.Container
	redis     testcontainers.Container
	nw        *testcontainers.DockerNetwork
	keyDir    string
	hibpMock  *mocks.HIBPMock
	emailMock *mocks.EmailSinkMock
}

// setupSuite boots Postgres, Redis, and the SUT image on a shared Docker
// network, runs migrations, waits for the SUT to report ready, and returns
// an Env plus a teardown func. On any failure it tears down whatever was
// already started before returning the error.
func setupSuite(ctx context.Context) (*Env, func(), error) {
	var res suiteResources
	teardown := func() { teardownSuite(&res) }

	repoRoot, err := repoRoot()
	if err != nil {
		return nil, teardown, fmt.Errorf("resolve repo root: %w", err)
	}

	keyDir, err := os.MkdirTemp("", "auth-e2e-keys-")
	if err != nil {
		return nil, teardown, fmt.Errorf("create temp key dir: %w", err)
	}
	res.keyDir = keyDir

	hostKeyPath, err := generateES256KeyFile(keyDir)
	if err != nil {
		return nil, teardown, fmt.Errorf("generate ES256 test key: %w", err)
	}

	nw, err := network.New(ctx)
	if err != nil {
		return nil, teardown, fmt.Errorf("create docker network: %w", err)
	}
	res.nw = nw

	pgContainer, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase(fakePostgresDB),
		tcpostgres.WithUsername(fakePostgresUser),
		tcpostgres.WithPassword(fakePostgresPassword),
		tcpostgres.BasicWaitStrategies(),
		network.WithNetwork([]string{postgresAlias}, nw),
	)
	if err != nil {
		return nil, teardown, fmt.Errorf("start postgres testcontainer: %w", err)
	}
	res.postgres = pgContainer

	redisContainer, err := tcredis.Run(ctx, redisImage,
		network.WithNetwork([]string{redisAlias}, nw),
	)
	if err != nil {
		return nil, teardown, fmt.Errorf("start redis testcontainer: %w", err)
	}
	res.redis = redisContainer

	databaseURL := fmt.Sprintf("postgres://%s:%s@%s:5432/%s?sslmode=disable",
		fakePostgresUser, fakePostgresPassword, postgresAlias, fakePostgresDB)

	if err := runMigrations(ctx, repoRoot, nw.Name, databaseURL); err != nil {
		return nil, teardown, fmt.Errorf("run migrations: %w", err)
	}

	// External-service fakes: started on the host (not the Docker network)
	// and reached by the SUT container over testcontainers host-port access
	// (host.testcontainers.internal), exactly as it would reach the real
	// HIBP/email services.
	hibpPort, emailPort, err := startMocks(&res)
	if err != nil {
		return nil, teardown, err
	}

	sutContainer, err := startSUT(ctx, repoRoot, nw.Name, hostKeyPath, hibpPort, emailPort)
	if err != nil {
		return nil, teardown, fmt.Errorf("start SUT container: %w", err)
	}
	res.sut = sutContainer

	publicBaseURL, err := containerBaseURL(ctx, sutContainer, sutPublicPort)
	if err != nil {
		return nil, teardown, fmt.Errorf("resolve SUT public endpoint: %w", err)
	}
	adminBaseURL, err := containerBaseURL(ctx, sutContainer, sutAdminPort)
	if err != nil {
		return nil, teardown, fmt.Errorf("resolve SUT admin endpoint: %w", err)
	}
	grpcHost, err := sutContainer.Host(ctx)
	if err != nil {
		return nil, teardown, fmt.Errorf("resolve SUT host: %w", err)
	}
	grpcPort, err := sutContainer.MappedPort(ctx, sutGRPCPort)
	if err != nil {
		return nil, teardown, fmt.Errorf("resolve SUT grpc port: %w", err)
	}

	if err := waitForReadiness(ctx, publicBaseURL+"/readiness", sutContainer); err != nil {
		return nil, teardown, err
	}

	env := &Env{
		PublicBaseURL: publicBaseURL,
		AdminBaseURL:  adminBaseURL,
		GRPCAddr:      fmt.Sprintf("%s:%s", grpcHost, grpcPort.Port()),
		HTTPClient:    &http.Client{Timeout: 15 * time.Second},
		EmailSink:     res.emailMock,
		HIBP:          res.hibpMock,
	}
	return env, teardown, nil
}

// startMocks starts the host-bound HIBP/email fakes and resolves the ports
// the SUT reaches them on via testcontainers host-port access. Resources are
// registered on res as soon as they're created so teardownSuite releases
// them even if port resolution subsequently fails.
func startMocks(res *suiteResources) (hibpPort, emailPort int, err error) {
	hibpMock := mocks.NewHIBPMock()
	res.hibpMock = hibpMock
	hibpPort, err = hibpMock.Port()
	if err != nil {
		return 0, 0, fmt.Errorf("resolve HIBP mock port: %w", err)
	}

	emailMock := mocks.NewEmailSinkMock()
	res.emailMock = emailMock
	emailPort, err = emailMock.Port()
	if err != nil {
		return 0, 0, fmt.Errorf("resolve email sink mock port: %w", err)
	}

	return hibpPort, emailPort, nil
}

// teardownSuite terminates every container and removes the network,
// swallowing individual errors (best-effort) so one failure doesn't block
// releasing the rest. Intended to leave zero containers/networks behind,
// backstopped by the testcontainers reaper (Ryuk) if the process is killed
// before this runs.
func teardownSuite(res *suiteResources) {
	ctx := context.Background()

	if res.sut != nil {
		_ = testcontainers.TerminateContainer(res.sut)
	}
	if res.postgres != nil {
		_ = testcontainers.TerminateContainer(res.postgres)
	}
	if res.redis != nil {
		_ = testcontainers.TerminateContainer(res.redis)
	}
	if res.nw != nil {
		_ = res.nw.Remove(ctx)
	}
	if res.keyDir != "" {
		_ = os.RemoveAll(res.keyDir)
	}
	if res.hibpMock != nil {
		res.hibpMock.Close()
	}
	if res.emailMock != nil {
		res.emailMock.Close()
	}
}

// runMigrations runs the SUT image with its entrypoint overridden to
// /auth-migrate and blocks until the container exits, failing (with
// captured logs) on a non-zero exit code.
func runMigrations(ctx context.Context, repoRoot, networkName, databaseURL string) error {
	req := imageRequest(repoRoot)
	req.Entrypoint = []string{"/auth-migrate"}
	req.Cmd = []string{"up"}
	req.Env = map[string]string{"DATABASE_URL": databaseURL}
	req.Networks = []string{networkName}
	req.WaitingFor = wait.ForExit().WithExitTimeout(migrationExitTimeout)

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if c != nil {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
	}
	if err != nil {
		return fmt.Errorf("start migration container: %w", err)
	}

	state, err := c.State(ctx)
	if err != nil {
		return fmt.Errorf("inspect migration container state: %w", err)
	}
	if state.ExitCode != 0 {
		return fmt.Errorf("migration container exited %d, logs:\n%s", state.ExitCode, containerLogs(ctx, c))
	}
	return nil
}

// startSUT builds/pulls the SUT image, mounts the generated ES256 key, and
// starts the server container on networkName. hibpPort/emailPort are the
// host ports the HIBPMock/EmailSinkMock fakes are listening on; the SUT
// reaches them via testcontainers host-port access
// (host.testcontainers.internal) exactly as it would reach the real
// services. It does not itself wait for application readiness (see
// waitForReadiness); it only waits for the public port to start listening
// so the caller can begin polling.
func startSUT(ctx context.Context, repoRoot, networkName, hostKeyPath string, hibpPort, emailPort int) (testcontainers.Container, error) {
	req := imageRequest(repoRoot)
	req.ExposedPorts = []string{sutPublicPort, sutAdminPort, sutGRPCPort}
	req.Networks = []string{networkName}
	req.NetworkAliases = map[string][]string{networkName: {"auth-service"}}
	req.HostAccessPorts = []int{hibpPort, emailPort}
	req.Files = []testcontainers.ContainerFile{
		{
			HostFilePath:      hostKeyPath,
			ContainerFilePath: containerKeyPath,
			FileMode:          0o644,
		},
	}
	req.Env = map[string]string{
		"APP_ENV":                 "development",
		"LOG_LEVEL":               "info",
		"POSTGRES_HOST":           postgresAlias,
		"POSTGRES_PORT":           "5432",
		"POSTGRES_DB":             fakePostgresDB,
		"POSTGRES_USER":           fakePostgresUser,
		"POSTGRES_PASSWORD":       fakePostgresPassword,
		"POSTGRES_SSLMODE":        "disable",
		"REDIS_HOST":              redisAlias,
		"REDIS_PORT":              "6379",
		"JWT_PRIVATE_KEY_PATH":    containerKeyPath,
		"JWT_ALGORITHM":           "ES256",
		"SYSTEM_SECRETS":          fakeSystemSecret,
		"PASSWORD_PEPPER":         fakePasswordPepper,
		"CORS_ALLOWED_ORIGINS":    fakeCORSOrigin,
		"HIBP_API_URL":            fmt.Sprintf("http://%s:%d/range/", testcontainers.HostInternal, hibpPort),
		"EMAIL_ENABLED":           "true",
		"EMAIL_SERVICE_URL":       fmt.Sprintf("http://%s:%d", testcontainers.HostInternal, emailPort),
		"EMAIL_API_KEY":           fakeEmailAPIKey,
		"EMAIL_SENDER_ADDRESS":    fakeEmailSenderAddress,
		"PASSWORD_RESET_URL_BASE": fakePasswordResetURLBase,
		"EMAIL_VERIFY_URL_BASE":   fakeEmailVerifyURLBase,
		"OIDC_LOGIN_UI_URL":       fakeOIDCLoginUIURL,
	}
	req.WaitingFor = wait.ForListeningPort(sutPublicPort).WithStartupTimeout(containerStartTimeout)

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		if c != nil {
			err = fmt.Errorf("%w, logs:\n%s", err, containerLogs(ctx, c))
			_ = testcontainers.TerminateContainer(c)
		}
		return nil, err
	}
	return c, nil
}

// imageRequest returns a fresh ContainerRequest pointed at either E2E_IMAGE
// (set by CI, which builds the image once) or a from-Dockerfile build
// (local dev fallback). Callers customize the returned value further
// (entrypoint, env, ports) without affecting other callers.
func imageRequest(repoRoot string) testcontainers.ContainerRequest {
	if img := os.Getenv("E2E_IMAGE"); img != "" {
		return testcontainers.ContainerRequest{Image: img}
	}
	return testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:       repoRoot,
			Dockerfile:    filepath.Join("docker", "Dockerfile"),
			PrintBuildLog: true,
			KeepImage:     false,
		},
	}
}

// waitForReadiness polls readinessURL until it returns 200, up to
// readinessTimeout, failing fast with the SUT's container logs attached so
// a broken boot is diagnosable from CI output alone.
func waitForReadiness(ctx context.Context, readinessURL string, sut testcontainers.Container) error {
	deadline := time.Now().Add(readinessTimeout)
	client := &http.Client{Timeout: 5 * time.Second}

	var lastErr error
	for time.Now().Before(deadline) {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, readinessURL, http.NoBody)
		if err != nil {
			cancel()
			return fmt.Errorf("build readiness request: %w", err)
		}
		resp, err := client.Do(req)
		cancel()
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("readiness returned status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(readinessPollEvery)
	}

	return fmt.Errorf("SUT did not become ready at %s within %s: %w, logs:\n%s",
		readinessURL, readinessTimeout, lastErr, containerLogs(ctx, sut))
}

// containerBaseURL resolves a container's mapped host port into an
// "http://host:port" base URL.
func containerBaseURL(ctx context.Context, c testcontainers.Container, containerPort string) (string, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return "", err
	}
	mapped, err := c.MappedPort(ctx, containerPort)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("http://%s:%s", host, mapped.Port()), nil
}

// containerLogs best-effort reads all container logs for inclusion in
// failure messages; it never returns an error, only a diagnostic string.
func containerLogs(ctx context.Context, c testcontainers.Container) string {
	if c == nil {
		return "(no container)"
	}
	rc, err := c.Logs(ctx)
	if err != nil {
		return fmt.Sprintf("(failed to fetch logs: %v)", err)
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Sprintf("(failed to read logs: %v)", err)
	}
	return string(data)
}

// generateES256KeyFile generates a fresh P-256 EC key pair and writes the
// private key as a PKCS#8 PEM file (matching internal/token.parsePrivateKey)
// into dir, returning its host path.
func generateES256KeyFile(dir string) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate EC key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal PKCS8 key: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}

	path := filepath.Join(dir, "jwt-private.pem")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // path is filepath.Join of a dir we created via os.MkdirTemp, not user input
	if err != nil {
		return "", fmt.Errorf("create key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return "", fmt.Errorf("write PEM: %w", err)
	}
	return path, nil
}

// repoRoot resolves the repository root as the parent directory of this
// package (e2e/ lives directly at the repo root), so FromDockerfile builds
// use the same build context "docker build" from the repo root would.
func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("resolve caller for repo root")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
