package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// jwk mirrors the EC/P-256 JSON Web Key shape written by
// internal/token.Service.publicKeyToJWK (RFC 7517).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksResponse mirrors api.JWKSResponse's JSON shape.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// fetchJWKSKeyfunc fetches the SUT's live JWKS document over HTTP and
// returns a jwt.Keyfunc that resolves any token's "kid" (or, absent a
// matching kid, the sole key) to the corresponding *ecdsa.PublicKey. Flow
// tests use this instead of a locally-shared key so JWT verification
// exercises the real JWKS endpoint (the GH-488 regression this task guards
// against was specifically about roles surviving the real issuance path).
func fetchJWKSKeyfunc(ctx context.Context, client *http.Client, publicBaseURL string) (jwt.Keyfunc, error) {
	keys, err := fetchJWKS(ctx, client, publicBaseURL)
	if err != nil {
		return nil, err
	}

	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("no keys in JWKS")
		}

		kid, _ := token.Header["kid"].(string)
		for _, k := range keys {
			if kid == "" || k.Kid == kid {
				return jwkToECDSAPublicKey(k)
			}
		}
		// Fall back to the first key if kid didn't match anything (single-key
		// JWKS, as configured by this harness).
		return jwkToECDSAPublicKey(keys[0])
	}, nil
}

// fetchJWKS fetches and decodes the JWKS document from
// publicBaseURL+"/.well-known/jwks.json".
func fetchJWKS(ctx context.Context, client *http.Client, publicBaseURL string) ([]jwk, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicBaseURL+"/.well-known/jwks.json", http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	var parsed jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	return parsed.Keys, nil
}

// jwkToECDSAPublicKey reconstructs a P-256 *ecdsa.PublicKey from a JWK's
// base64url-encoded (RawURLEncoding) x/y coordinates.
func jwkToECDSAPublicKey(k jwk) (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported jwk kty/crv: %s/%s", k.Kty, k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode jwk x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode jwk y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
