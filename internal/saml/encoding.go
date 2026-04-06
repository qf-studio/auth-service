package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
)

// deflateAndEncode compresses data with DEFLATE and base64-encodes it
// for SAML HTTP-Redirect binding.
func deflateAndEncode(data []byte) (string, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("create deflate writer: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return "", fmt.Errorf("deflate write: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("deflate close: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// decodeAndInflate base64-decodes and DEFLATE-decompresses SAML data.
func decodeAndInflate(encoded string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	r := flate.NewReader(bytes.NewReader(compressed))
	defer func() { _ = r.Close() }()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("inflate: %w", err)
	}
	return data, nil
}
