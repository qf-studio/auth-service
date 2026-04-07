package mocks_test

import (
	"testing"

	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

func TestInterfaceCompliance(t *testing.T) {
	// Compile-time checks that mocks satisfy their interfaces.
	var _ storage.UserRepository = (*mocks.MockUserRepository)(nil)
	var _ storage.AdminUserRepository = (*mocks.MockAdminUserRepository)(nil)
	var _ storage.ClientRepository = (*mocks.MockClientRepository)(nil)
	var _ storage.RefreshTokenRepository = (*mocks.MockRefreshTokenRepository)(nil)
	var _ storage.OAuthAccountRepository = (*mocks.MockOAuthAccountRepository)(nil)
	var _ storage.TenantRepository = (*mocks.MockTenantRepository)(nil)
	var _ storage.MFARepository = (*mocks.MockMFARepository)(nil)
	var _ storage.WebhookRepository = (*mocks.MockWebhookRepository)(nil)
	var _ storage.WebhookDeliveryRepository = (*mocks.MockWebhookDeliveryRepository)(nil)
	var _ storage.AuditReadRepository = (*mocks.MockAuditReadRepository)(nil)
	var _ storage.RARRepository = (*mocks.MockRARRepository)(nil)
	var _ storage.SAMLAccountRepository = (*mocks.MockSAMLAccountRepository)(nil)
	var _ storage.SAMLIdPRepository = (*mocks.MockSAMLIdPRepository)(nil)
	var _ storage.WebAuthnCredentialRepository = (*mocks.MockWebAuthnCredentialRepository)(nil)
	var _ storage.APIKeyRepository = (*mocks.MockAPIKeyRepository)(nil)
}
