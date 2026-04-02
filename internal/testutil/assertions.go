//go:build integration

package testutil

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AssertErrorCode verifies that the HTTP response contains an ErrorResponse with the expected code.
func AssertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, expectedStatus int, expectedCode string) {
	t.Helper()

	assert.Equal(t, expectedStatus, rec.Code, "unexpected HTTP status")

	var errResp domain.ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &errResp)
	require.NoError(t, err, "failed to unmarshal error response")
	assert.Equal(t, expectedCode, errResp.Code, "unexpected error code")
}

// AssertErrorMessage verifies the error message in an ErrorResponse.
func AssertErrorMessage(t *testing.T, rec *httptest.ResponseRecorder, expectedMessage string) {
	t.Helper()

	var errResp domain.ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &errResp)
	require.NoError(t, err, "failed to unmarshal error response")
	assert.Equal(t, expectedMessage, errResp.Error, "unexpected error message")
}

// AssertValidationError verifies that the response is a 422 validation error
// and that at least one validation detail references the expected field.
func AssertValidationError(t *testing.T, rec *httptest.ResponseRecorder, expectedField string) {
	t.Helper()

	assert.Equal(t, 422, rec.Code, "expected 422 Unprocessable Entity")

	var errResp struct {
		Error   string                        `json:"error"`
		Code    string                        `json:"code"`
		Details []domain.ValidationErrorDetail `json:"details"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &errResp)
	require.NoError(t, err, "failed to unmarshal validation error response")

	assert.Equal(t, domain.CodeValidationError, errResp.Code)

	var found bool
	for _, d := range errResp.Details {
		if d.Field == expectedField {
			found = true
			break
		}
	}
	assert.True(t, found, "expected validation error for field %q, got details: %+v", expectedField, errResp.Details)
}

// AssertJSONField verifies that a specific top-level field in the JSON response has the expected value.
func AssertJSONField(t *testing.T, rec *httptest.ResponseRecorder, field string, expected interface{}) {
	t.Helper()

	var body map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &body)
	require.NoError(t, err, "failed to unmarshal JSON response")

	actual, ok := body[field]
	require.True(t, ok, "field %q not found in response", field)
	assert.Equal(t, expected, actual, "unexpected value for field %q", field)
}

// ParseJSON unmarshals the response body into the provided target.
func ParseJSON(t *testing.T, rec *httptest.ResponseRecorder, target interface{}) {
	t.Helper()
	err := json.Unmarshal(rec.Body.Bytes(), target)
	require.NoError(t, err, "failed to unmarshal response body")
}
