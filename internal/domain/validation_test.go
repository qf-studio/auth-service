package domain_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestNewValidator_NistPassword(t *testing.T) {
	v := domain.NewValidator()

	tests := []struct {
		name    string
		req     domain.RegisterRequest
		wantErr bool
	}{
		{
			name: "valid password (exactly 15 chars)",
			req: domain.RegisterRequest{
				Email:    "user@example.com",
				Password: "abcdefghijklmno", // 15 chars
				Name:     "Test User",
			},
			wantErr: false,
		},
		{
			name: "valid password (longer than minimum)",
			req: domain.RegisterRequest{
				Email:    "user@example.com",
				Password: "this-is-a-very-secure-passphrase",
				Name:     "Test User",
			},
			wantErr: false,
		},
		{
			name: "short password (14 chars)",
			req: domain.RegisterRequest{
				Email:    "user@example.com",
				Password: "abcdefghijklmn", // 14 chars
				Name:     "Test User",
			},
			wantErr: true,
		},
		{
			name: "empty password",
			req: domain.RegisterRequest{
				Email:    "user@example.com",
				Password: "",
				Name:     "Test User",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewValidator_RegisterRequest(t *testing.T) {
	v := domain.NewValidator()

	tests := []struct {
		name      string
		req       domain.RegisterRequest
		wantErr   bool
		wantField string
	}{
		{
			name: "valid registration",
			req: domain.RegisterRequest{
				Email:    "user@example.com",
				Password: "super-secure-password-123",
				Name:     "Alice",
			},
			wantErr: false,
		},
		{
			name: "missing email",
			req: domain.RegisterRequest{
				Password: "super-secure-password-123",
				Name:     "Alice",
			},
			wantErr:   true,
			wantField: "Email",
		},
		{
			name: "invalid email format",
			req: domain.RegisterRequest{
				Email:    "not-an-email",
				Password: "super-secure-password-123",
				Name:     "Alice",
			},
			wantErr:   true,
			wantField: "Email",
		},
		{
			name: "missing name",
			req: domain.RegisterRequest{
				Email:    "user@example.com",
				Password: "super-secure-password-123",
			},
			wantErr:   true,
			wantField: "Name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantField != "" {
					assert.Contains(t, err.Error(), tt.wantField)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewValidator_LoginRequest(t *testing.T) {
	v := domain.NewValidator()

	tests := []struct {
		name    string
		req     domain.LoginRequest
		wantErr bool
	}{
		{
			name:    "valid login",
			req:     domain.LoginRequest{Email: "user@example.com", Password: "any-password"},
			wantErr: false,
		},
		{
			name:    "missing email",
			req:     domain.LoginRequest{Password: "any-password"},
			wantErr: true,
		},
		{
			name:    "missing password",
			req:     domain.LoginRequest{Email: "user@example.com"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewValidator_TokenRefreshRequest(t *testing.T) {
	v := domain.NewValidator()

	tests := []struct {
		name    string
		req     domain.TokenRefreshRequest
		wantErr bool
	}{
		{
			name:    "valid refresh",
			req:     domain.TokenRefreshRequest{RefreshToken: "qf_rt_abc123"},
			wantErr: false,
		},
		{
			name:    "missing refresh token",
			req:     domain.TokenRefreshRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewValidator_PasswordResetRequest(t *testing.T) {
	v := domain.NewValidator()

	tests := []struct {
		name    string
		req     domain.PasswordResetRequest
		wantErr bool
	}{
		{
			name:    "valid request",
			req:     domain.PasswordResetRequest{Email: "user@example.com"},
			wantErr: false,
		},
		{
			name:    "missing email",
			req:     domain.PasswordResetRequest{},
			wantErr: true,
		},
		{
			name:    "invalid email",
			req:     domain.PasswordResetRequest{Email: "bad"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewValidator_PasswordResetConfirmRequest(t *testing.T) {
	v := domain.NewValidator()

	tests := []struct {
		name    string
		req     domain.PasswordResetConfirmRequest
		wantErr bool
	}{
		{
			name: "valid confirm",
			req: domain.PasswordResetConfirmRequest{
				Token:       "reset-token-abc",
				NewPassword: "a-very-long-new-password",
			},
			wantErr: false,
		},
		{
			name: "short new password",
			req: domain.PasswordResetConfirmRequest{
				Token:       "reset-token-abc",
				NewPassword: "short",
			},
			wantErr: true,
		},
		{
			name: "missing token",
			req: domain.PasswordResetConfirmRequest{
				NewPassword: "a-very-long-new-password",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- Middleware integration tests ---

func TestValidateRequest_ValidBody(t *testing.T) {
	v := domain.NewValidator()
	router := gin.New()
	router.POST("/register", domain.ValidateRequest(v, func() interface{} {
		return &domain.RegisterRequest{}
	}), func(c *gin.Context) {
		req, exists := c.Get("validated_request")
		assert.True(t, exists)
		regReq, ok := req.(*domain.RegisterRequest)
		assert.True(t, ok)
		assert.Equal(t, "user@example.com", regReq.Email)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	body := `{"email":"user@example.com","password":"super-secure-password-123","name":"Alice"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateRequest_InvalidJSON(t *testing.T) {
	v := domain.NewValidator()
	router := gin.New()
	router.POST("/register", domain.ValidateRequest(v, func() interface{} {
		return &domain.RegisterRequest{}
	}))

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{bad json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp domain.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, domain.CodeBadRequest, resp.Code)
}

func TestValidateRequest_ValidationErrors(t *testing.T) {
	v := domain.NewValidator()
	router := gin.New()
	router.POST("/register", domain.ValidateRequest(v, func() interface{} {
		return &domain.RegisterRequest{}
	}))

	// Missing name, short password
	body := `{"email":"user@example.com","password":"short"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	var resp domain.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, domain.CodeValidationError, resp.Code)
	assert.Equal(t, "Validation failed", resp.Error)

	details, ok := resp.Details.([]interface{})
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(details), 2) // password + name errors
}

func TestValidateRequest_PasswordExactlyMinLength(t *testing.T) {
	v := domain.NewValidator()
	router := gin.New()
	router.POST("/register", domain.ValidateRequest(v, func() interface{} {
		return &domain.RegisterRequest{}
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Exactly 15 characters
	password := strings.Repeat("a", domain.NistMinPasswordLength)
	body, _ := json.Marshal(map[string]string{
		"email":    "user@example.com",
		"password": password,
		"name":     "Test",
	})

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateRequest_NoCompositionRules(t *testing.T) {
	v := domain.NewValidator()
	router := gin.New()
	router.POST("/register", domain.ValidateRequest(v, func() interface{} {
		return &domain.RegisterRequest{}
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// NIST: no composition rules — all-lowercase password is valid if >= 15 chars
	body := `{"email":"user@example.com","password":"alllowercasepassword","name":"Test"}`
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateRequest_LoginRequest(t *testing.T) {
	v := domain.NewValidator()
	router := gin.New()
	router.POST("/login", domain.ValidateRequest(v, func() interface{} {
		return &domain.LoginRequest{}
	}), func(c *gin.Context) {
		req, _ := c.Get("validated_request")
		loginReq := req.(*domain.LoginRequest)
		c.JSON(http.StatusOK, gin.H{"email": loginReq.Email})
	})

	body := `{"email":"user@example.com","password":"any-password"}`
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestValidateRequest_EmptyBody(t *testing.T) {
	v := domain.NewValidator()
	router := gin.New()
	router.POST("/login", domain.ValidateRequest(v, func() interface{} {
		return &domain.LoginRequest{}
	}))

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
