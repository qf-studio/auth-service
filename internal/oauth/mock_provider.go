package oauth

import (
	"context"
	"fmt"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockProvider is a test-only Provider that returns configurable results.
type MockProvider struct {
	ProviderName     domain.OAuthProviderType
	AuthURL          string
	ExchangeToken    string
	ExchangeErr      error
	UserResult       *domain.OAuthUser
	UserErr          error
}

func (m *MockProvider) Name() domain.OAuthProviderType {
	return m.ProviderName
}

func (m *MockProvider) GetAuthURL(state, codeChallenge string) string {
	if m.AuthURL != "" {
		return fmt.Sprintf("%s?state=%s&code_challenge=%s", m.AuthURL, state, codeChallenge)
	}
	return fmt.Sprintf("https://mock.example.com/auth?state=%s&code_challenge=%s", state, codeChallenge)
}

func (m *MockProvider) ExchangeCode(_ context.Context, _, _ string) (string, error) {
	if m.ExchangeErr != nil {
		return "", m.ExchangeErr
	}
	if m.ExchangeToken != "" {
		return m.ExchangeToken, nil
	}
	return "mock-access-token", nil
}

func (m *MockProvider) GetUser(_ context.Context, _ string) (*domain.OAuthUser, error) {
	if m.UserErr != nil {
		return nil, m.UserErr
	}
	if m.UserResult != nil {
		return m.UserResult, nil
	}
	return &domain.OAuthUser{
		ProviderUserID: "mock-user-123",
		Email:          "mock@example.com",
		Name:           "Mock User",
	}, nil
}
