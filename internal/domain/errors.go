package domain

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Error code constants for structured API error responses.
const (
	CodeValidationError  = "VALIDATION_ERROR"
	CodeUnauthorized     = "UNAUTHORIZED"
	CodeForbidden        = "FORBIDDEN"
	CodeNotFound         = "NOT_FOUND"
	CodeRateLimitExceded = "RATE_LIMIT_EXCEEDED"
	CodeInternalError    = "INTERNAL_ERROR"
	CodeBadRequest       = "BAD_REQUEST"
)

// ErrorResponse is the standard JSON error envelope returned by all API endpoints.
type ErrorResponse struct {
	Error   string      `json:"error"`
	Code    string      `json:"code"`
	Details interface{} `json:"details,omitempty"`
}

// ValidationErrorDetail represents a single field-level validation failure.
type ValidationErrorDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// RespondWithError writes a structured JSON error response and aborts the Gin context.
func RespondWithError(c *gin.Context, status int, code string, message string) {
	c.AbortWithStatusJSON(status, ErrorResponse{
		Error: message,
		Code:  code,
	})
}

// RespondWithValidationErrors writes a 422 response with per-field validation details.
func RespondWithValidationErrors(c *gin.Context, details []ValidationErrorDetail) {
	c.AbortWithStatusJSON(http.StatusUnprocessableEntity, ErrorResponse{
		Error:   "Validation failed",
		Code:    CodeValidationError,
		Details: details,
	})
}
