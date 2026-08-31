package e2e

// Fake, non-production values used only to boot the SUT (system under test)
// container inside the e2e harness against ephemeral, throwaway
// testcontainers. None of these are ever used against a real deployment;
// they are deliberately obvious placeholders so GitHub push-protection does
// not (incorrectly) flag them as leaked credentials.
const (
	// fakePostgresUser/fakePostgresPassword/fakePostgresDB configure the
	// throwaway Postgres testcontainer and the SUT's POSTGRES_* env vars.
	fakePostgresUser     = "e2e_test_user"
	fakePostgresPassword = "e2e-not-a-real-postgres-password" //nolint:gosec // fake, test-only
	fakePostgresDB       = "auth_e2e"

	// fakeSystemSecret seeds SYSTEM_SECRETS (HMAC pepper input for
	// service-to-service secrets, unrelated to user passwords).
	fakeSystemSecret = "e2e-not-a-real-system-secret-0000000000" //nolint:gosec // fake, test-only

	// fakePasswordPepper seeds PASSWORD_PEPPER for Argon2id hashing.
	fakePasswordPepper = "e2e-not-a-real-password-pepper" //nolint:gosec // fake, test-only

	// fakeCORSOrigin satisfies the required CORS_ALLOWED_ORIGINS env var;
	// the harness never exercises browser CORS behavior.
	fakeCORSOrigin = "http://localhost:3000"

	// fakeUserPassword is used to register/login golden-path test users.
	// Must clear the NIST SP 800-63-4 15-character minimum (no composition
	// rules apply); it is not a real credential for any account.
	fakeUserPassword = "correct horse battery staple e2e" //nolint:gosec // fake, test-only
)
