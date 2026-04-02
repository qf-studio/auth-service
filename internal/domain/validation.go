package domain

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// NistMinPasswordLength is the minimum password length per NIST SP 800-63-4.
// No composition rules (uppercase, symbols, etc.) are enforced.
const NistMinPasswordLength = 15

// --- Request structs ---

// RegisterRequest is the validated request body for user registration.
type RegisterRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,nist_password"`
	Name     string `json:"name"     validate:"required,min=1,max=255"`
}

// LoginRequest is the validated request body for user login.
type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// TokenRefreshRequest is the validated request body for refreshing an access token.
type TokenRefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// PasswordResetRequest is the validated request body for initiating a password reset.
type PasswordResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// PasswordResetConfirmRequest is the validated request body for completing a password reset.
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"        validate:"required"`
	NewPassword string `json:"new_password" validate:"required,nist_password"`
}

// TokenRequest is the validated request body for the unified /auth/token endpoint.
// It dispatches based on grant_type: "refresh_token" or "client_credentials".
type TokenRequest struct {
	GrantType    string `json:"grant_type"    validate:"required,oneof=refresh_token client_credentials"`
	RefreshToken string `json:"refresh_token" validate:"required_if=GrantType refresh_token"`
	ClientID     string `json:"client_id"     validate:"required_if=GrantType client_credentials"`
	ClientSecret string `json:"client_secret" validate:"required_if=GrantType client_credentials"`
}

// RevokeRequest is the validated request body for token revocation.
type RevokeRequest struct {
	Token string `json:"token" validate:"required"`
}

// PasswordChangeRequest is the validated request body for changing a password (authenticated).
type PasswordChangeRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,nist_password"`
}

// --- Validator setup ---

// NewValidator creates a validator.Validate instance with custom NIST password validation registered.
func NewValidator() *validator.Validate {
	v := validator.New()
	_ = v.RegisterValidation("nist_password", validateNistPassword)
	return v
}

// validateNistPassword enforces NIST SP 800-63-4 password policy:
// minimum 15 characters, no composition rules, no periodic rotation.
func validateNistPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()
	return len(password) >= NistMinPasswordLength
}

// --- Validation middleware ---

// ValidateRequest returns Gin middleware that binds JSON, validates using the provided
// validator, and stores the validated struct in the Gin context under "validated_request".
// The reqFactory function must return a pointer to a new zero-valued request struct.
func ValidateRequest(v *validator.Validate, reqFactory func() interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := reqFactory()

		if err := c.ShouldBindJSON(req); err != nil {
			RespondWithError(c, http.StatusBadRequest, CodeBadRequest, "Invalid request body")
			return
		}

		if err := v.Struct(req); err != nil {
			validationErrs, ok := err.(validator.ValidationErrors)
			if !ok {
				RespondWithError(c, http.StatusBadRequest, CodeBadRequest, "Validation failed")
				return
			}

			details := make([]ValidationErrorDetail, 0, len(validationErrs))
			for _, fe := range validationErrs {
				details = append(details, ValidationErrorDetail{
					Field:   jsonFieldName(fe),
					Message: validationMessage(fe),
				})
			}

			RespondWithValidationErrors(c, details)
			return
		}

		c.Set("validated_request", req)
		c.Next()
	}
}

// jsonFieldName returns the lowercase, JSON-style field name for a validation error.
func jsonFieldName(fe validator.FieldError) string {
	return strings.ToLower(fe.Field())
}

// validationMessage returns a human-readable message for a validation error.
func validationMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", strings.ToLower(fe.Field()))
	case "email":
		return "must be a valid email address"
	case "nist_password":
		return fmt.Sprintf("must be at least %d characters", NistMinPasswordLength)
	case "min":
		return fmt.Sprintf("must be at least %s characters", fe.Param())
	case "max":
		return fmt.Sprintf("must be at most %s characters", fe.Param())
	case "oneof":
		return fmt.Sprintf("must be one of: %s", fe.Param())
	case "required_if":
		return fmt.Sprintf("%s is required for this grant type", strings.ToLower(fe.Field()))
	default:
		return fmt.Sprintf("failed validation: %s", fe.Tag())
	}
}
