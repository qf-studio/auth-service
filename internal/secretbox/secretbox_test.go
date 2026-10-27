package secretbox

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testBox(t *testing.T) *Box {
	t.Helper()
	b, err := New(bytes.Repeat([]byte{0x42}, KeySize))
	require.NoError(t, err)
	return b
}

func TestDigest(t *testing.T) {
	d := Digest("abc")
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", d)
	assert.NotEqual(t, "abc", d)
	assert.Equal(t, d, Digest("abc"))
}

func TestBox_RoundTrip(t *testing.T) {
	b := testBox(t)
	sealed, err := b.Encrypt("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(sealed, "v1:"))
	assert.Len(t, strings.Split(sealed, ":"), 3)
	assert.NotContains(t, sealed, "JBSWY3DPEHPK3PXP")

	got, err := b.Decrypt(sealed)
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", got)
}

func TestBox_FreshNoncePerEncrypt(t *testing.T) {
	b := testBox(t)
	a, err := b.Encrypt("same")
	require.NoError(t, err)
	c, err := b.Encrypt("same")
	require.NoError(t, err)
	assert.NotEqual(t, a, c)
}

func TestBox_EncryptIsIdempotentOnSealedInput(t *testing.T) {
	b := testBox(t)
	sealed, err := b.Encrypt("x")
	require.NoError(t, err)
	again, err := b.Encrypt(sealed)
	require.NoError(t, err)
	assert.Equal(t, sealed, again)
}

func TestBox_LegacyPlaintextPassesThrough(t *testing.T) {
	got, err := testBox(t).Decrypt("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", got)
}

func TestBox_NilBoxIsPlaintext(t *testing.T) {
	var b *Box
	assert.False(t, b.Enabled())
	enc, err := b.Encrypt("secret")
	require.NoError(t, err)
	assert.Equal(t, "secret", enc)
	dec, err := b.Decrypt("secret")
	require.NoError(t, err)
	assert.Equal(t, "secret", dec)
}

func TestBox_NilBoxCannotReadSealed(t *testing.T) {
	sealed, err := testBox(t).Encrypt("secret")
	require.NoError(t, err)
	var b *Box
	_, err = b.Decrypt(sealed)
	assert.ErrorIs(t, err, ErrKeyRequired)
}

func TestBox_RejectsTamperingAndWrongKey(t *testing.T) {
	b := testBox(t)
	sealed, err := b.Encrypt("secret")
	require.NoError(t, err)

	parts := strings.Split(sealed, ":")
	ct, err := base64.StdEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	ct[0] ^= 0xff
	tampered := parts[0] + ":" + parts[1] + ":" + base64.StdEncoding.EncodeToString(ct)
	_, err = b.Decrypt(tampered)
	assert.Error(t, err)

	other, err := New(bytes.Repeat([]byte{0x01}, KeySize))
	require.NoError(t, err)
	_, err = other.Decrypt(sealed)
	assert.Error(t, err)

	for _, bad := range []string{"v1:", "v1:onlyone", "v1:a:b:c", "v1:!!!:!!!"} {
		_, err = b.Decrypt(bad)
		assert.Error(t, err, bad)
	}
}

func TestNew_KeyLength(t *testing.T) {
	_, err := New(make([]byte, 16))
	assert.Error(t, err)
}

func TestParseKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0x7f}, KeySize)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		key, err := ParseKey(enc.EncodeToString(raw))
		require.NoError(t, err)
		assert.Equal(t, raw, key)
	}
	_, err := ParseKey(base64.StdEncoding.EncodeToString(raw[:16]))
	assert.Error(t, err)
	_, err = ParseKey("not base64 !!")
	assert.Error(t, err)
}
