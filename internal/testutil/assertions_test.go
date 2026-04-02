//go:build integration

package testutil

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestAssertErrorCode(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := domain.ErrorResponse{
		Error: "not found",
		Code:  domain.CodeNotFound,
	}
	data, _ := json.Marshal(resp)
	rec.Code = 404
	_, _ = rec.Write(data)

	// Should not fail
	AssertErrorCode(t, rec, 404, domain.CodeNotFound)
}

func TestAssertErrorMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := domain.ErrorResponse{
		Error: "something went wrong",
		Code:  domain.CodeInternalError,
	}
	data, _ := json.Marshal(resp)
	_, _ = rec.Write(data)

	AssertErrorMessage(t, rec, "something went wrong")
}

func TestAssertValidationError(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := struct {
		Error   string                        `json:"error"`
		Code    string                        `json:"code"`
		Details []domain.ValidationErrorDetail `json:"details"`
	}{
		Error: "Validation failed",
		Code:  domain.CodeValidationError,
		Details: []domain.ValidationErrorDetail{
			{Field: "email", Message: "must be a valid email address"},
		},
	}
	data, _ := json.Marshal(resp)
	rec.Code = 422
	_, _ = rec.Write(data)

	AssertValidationError(t, rec, "email")
}

func TestAssertJSONField(t *testing.T) {
	rec := httptest.NewRecorder()
	data, _ := json.Marshal(map[string]interface{}{
		"token_type": "Bearer",
		"expires_in": float64(3600),
	})
	_, _ = rec.Write(data)

	AssertJSONField(t, rec, "token_type", "Bearer")
	AssertJSONField(t, rec, "expires_in", float64(3600))
}

func TestParseJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	resp := domain.ErrorResponse{
		Error: "test",
		Code:  domain.CodeBadRequest,
	}
	data, _ := json.Marshal(resp)
	_, _ = rec.Write(data)

	var parsed domain.ErrorResponse
	ParseJSON(t, rec, &parsed)

	assert.Equal(t, "test", parsed.Error)
	assert.Equal(t, domain.CodeBadRequest, parsed.Code)
}
