package password_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/qf-studio/auth-service/internal/password"
)

func generateBcryptHash(t *testing.T, pw string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	require.NoError(t, err)
	return string(hash)
}

func TestHash_ProducesValidPHCFormat(t *testing.T) {
	h := password.New(nil)
	hash, err := h.Hash("correct-horse-battery-staple")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$"), "hash must start with $argon2id$")

	parts := strings.Split(hash, "$")
	require.Len(t, parts, 6, "PHC format must have 6 dollar-separated segments")
	assert.Equal(t, "argon2id", parts[1])
	assert.Contains(t, parts[3], "m=19456")
	assert.Contains(t, parts[3], "t=2")
	assert.Contains(t, parts[3], "p=1")
}

func TestHash_ProducesUniqueHashesForSamePassword(t *testing.T) {
	h := password.New(nil)
	pw := "same-password-every-time"

	hash1, err := h.Hash(pw)
	require.NoError(t, err)

	hash2, err := h.Hash(pw)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "each call must produce a different salt → different hash")
}

func TestVerify_CorrectPassword(t *testing.T) {
	h := password.New(nil)
	pw := "my-super-secure-password-123"

	hash, err := h.Hash(pw)
	require.NoError(t, err)

	ok, err := h.Verify(pw, hash)
	require.NoError(t, err)
	assert.True(t, ok, "correct password must verify successfully")
}

func TestVerify_WrongPassword(t *testing.T) {
	h := password.New(nil)

	hash, err := h.Hash("the-real-password")
	require.NoError(t, err)

	ok, err := h.Verify("not-the-real-password", hash)
	require.NoError(t, err)
	assert.False(t, ok, "wrong password must not verify")
}

func TestVerify_InvalidHash(t *testing.T) {
	h := password.New(nil)

	_, err := h.Verify("any-password", "not-a-valid-hash")
	assert.ErrorIs(t, err, password.ErrInvalidHash)
}

func TestVerify_MalformedBase64Salt(t *testing.T) {
	h := password.New(nil)
	// Valid structure but corrupt salt field.
	malformed := "$argon2id$v=19$m=19456,t=2,p=1$!!!invalid!!!$YWJj"
	_, err := h.Verify("pw", malformed)
	assert.ErrorIs(t, err, password.ErrInvalidHash)
}

func TestVerify_MalformedBase64Key(t *testing.T) {
	h := password.New(nil)
	// Valid structure and salt but corrupt key field.
	malformed := "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$!!!invalid!!!"
	_, err := h.Verify("pw", malformed)
	assert.ErrorIs(t, err, password.ErrInvalidHash)
}

func TestHash_WithPepper(t *testing.T) {
	pepper := []byte("test-pepper-key-32-bytes-long!!!")
	h := password.New(pepper)
	pw := "peppered-password"

	hash, err := h.Hash(pw)
	require.NoError(t, err)

	ok, err := h.Verify(pw, hash)
	require.NoError(t, err)
	assert.True(t, ok, "pepper-enabled hasher must verify its own hash")
}

func TestVerify_PepperMismatch(t *testing.T) {
	pepper1 := []byte("pepper-one")
	pepper2 := []byte("pepper-two")
	pw := "some-password"

	hash, err := password.New(pepper1).Hash(pw)
	require.NoError(t, err)

	// A hasher with a different pepper should reject the hash.
	ok, err := password.New(pepper2).Verify(pw, hash)
	require.NoError(t, err)
	assert.False(t, ok, "different pepper must cause verification failure")
}

func TestVerify_NoPepperVsPepper(t *testing.T) {
	pw := "some-password"

	hash, err := password.New(nil).Hash(pw)
	require.NoError(t, err)

	ok, err := password.New([]byte("some-pepper")).Verify(pw, hash)
	require.NoError(t, err)
	assert.False(t, ok, "hasher with pepper must reject hash produced without pepper")
}

func TestNeedsUpgrade_BcryptHash(t *testing.T) {
	h := password.New(nil)
	assert.True(t, h.NeedsUpgrade("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"))
	assert.True(t, h.NeedsUpgrade("$2b$12$WApznUPhDubN0oeveSXHp.dznFJTijLnEByIdKmfzzqFoMRwIusn2"))
}

func TestNeedsUpgrade_Argon2idHash(t *testing.T) {
	h := password.New(nil)
	hash, err := h.Hash("test-password-123456")
	require.NoError(t, err)
	assert.False(t, h.NeedsUpgrade(hash))
}

func TestVerify_BcryptHash(t *testing.T) {
	h := password.New(nil)
	// bcrypt hash of "correct-horse-battery-staple" generated with cost 10.
	pw := "correct-horse-battery-staple"
	bcryptHash := generateBcryptHash(t, pw)

	ok, err := h.Verify(pw, bcryptHash)
	require.NoError(t, err)
	assert.True(t, ok, "bcrypt verification should succeed")
}

func TestVerify_BcryptHash_WrongPassword(t *testing.T) {
	h := password.New(nil)
	bcryptHash := generateBcryptHash(t, "correct-password")

	ok, err := h.Verify("wrong-password", bcryptHash)
	require.NoError(t, err)
	assert.False(t, ok, "bcrypt verification should fail with wrong password")
}

func TestHash_EmptyPassword(t *testing.T) {
	h := password.New(nil)
	// Empty passwords should still hash without error — policy enforcement is the caller's job.
	hash, err := h.Hash("")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

func BenchmarkHash_NoPepper(b *testing.B) {
	h := password.New(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := h.Hash("correct-horse-battery-staple")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHash_WithPepper(b *testing.B) {
	pepper := []byte("bench-pepper-key-32-bytes-long!!")
	h := password.New(pepper)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := h.Hash("correct-horse-battery-staple")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_NoPepper(b *testing.B) {
	h := password.New(nil)
	hash, err := h.Hash("correct-horse-battery-staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := h.Verify("correct-horse-battery-staple", hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_WithPepper(b *testing.B) {
	pepper := []byte("bench-pepper-key-32-bytes-long!!")
	h := password.New(pepper)
	hash, err := h.Hash("correct-horse-battery-staple")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := h.Verify("correct-horse-battery-staple", hash)
		if err != nil {
			b.Fatal(err)
		}
	}
}
