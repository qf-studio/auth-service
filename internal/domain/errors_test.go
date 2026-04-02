package domain_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestRespondWithError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		code       string
		message    string
		wantStatus int
		wantCode   string
		wantError  string
	}{
		{
			name:       "bad request",
			status:     http.StatusBadRequest,
			code:       domain.CodeBadRequest,
			message:    "invalid input",
			wantStatus: http.StatusBadRequest,
			wantCode:   "BAD_REQUEST",
			wantError:  "invalid input",
		},
		{
			name:       "unauthorized",
			status:     http.StatusUnauthorized,
			code:       domain.CodeUnauthorized,
			message:    "invalid credentials",
			wantStatus: http.StatusUnauthorized,
			wantCode:   "UNAUTHORIZED",
			wantError:  "invalid credentials",
		},
		{
			name:       "forbidden",
			status:     http.StatusForbidden,
			code:       domain.CodeForbidden,
			message:    "access denied",
			wantStatus: http.StatusForbidden,
			wantCode:   "FORBIDDEN",
			wantError:  "access denied",
		},
		{
			name:       "not found",
			status:     http.StatusNotFound,
			code:       domain.CodeNotFound,
			message:    "resource not found",
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
			wantError:  "resource not found",
		},
		{
			name:       "rate limit exceeded",
			status:     http.StatusTooManyRequests,
			code:       domain.CodeRateLimitExceded,
			message:    "too many requests",
			wantStatus: http.StatusTooManyRequests,
			wantCode:   "RATE_LIMIT_EXCEEDED",
			wantError:  "too many requests",
		},
		{
			name:       "internal error",
			status:     http.StatusInternalServerError,
			code:       domain.CodeInternalError,
			message:    "something went wrong",
			wantStatus: http.StatusInternalServerError,
			wantCode:   "INTERNAL_ERROR",
			wantError:  "something went wrong",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			domain.RespondWithError(c, tt.status, tt.code, tt.message)

			assert.Equal(t, tt.wantStatus, w.Code)

			var resp domain.ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantError, resp.Error)
			assert.Equal(t, tt.wantCode, resp.Code)
			assert.Nil(t, resp.Details)
		})
	}
}

func TestRespondWithError_AbortsContext(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "denied")

	assert.True(t, c.IsAborted())
}

func TestRespondWithValidationErrors(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	details := []domain.ValidationErrorDetail{
		{Field: "email", Message: "must be a valid email address"},
		{Field: "password", Message: "must be at least 15 characters"},
	}

	domain.RespondWithValidationErrors(c, details)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.True(t, c.IsAborted())

	var resp domain.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Validation failed", resp.Error)
	assert.Equal(t, domain.CodeValidationError, resp.Code)

	// Details is deserialized as []interface{} by default JSON unmarshalling
	detailsList, ok := resp.Details.([]interface{})
	require.True(t, ok)
	assert.Len(t, detailsList, 2)

	first, ok := detailsList[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "email", first["field"])
	assert.Equal(t, "must be a valid email address", first["message"])
}

func TestRespondWithValidationErrors_EmptyDetails(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	domain.RespondWithValidationErrors(c, []domain.ValidationErrorDetail{})

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	var resp domain.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, domain.CodeValidationError, resp.Code)
}

func TestErrorResponse_JSONOmitsEmptyDetails(t *testing.T) {
	resp := domain.ErrorResponse{
		Error: "not found",
		Code:  domain.CodeNotFound,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, hasDetails := raw["details"]
	assert.False(t, hasDetails, "details should be omitted when nil")
}
