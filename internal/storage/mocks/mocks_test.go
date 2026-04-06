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
	var _ storage.GDPRConsentRepository = (*mocks.MockGDPRConsentRepository)(nil)
	var _ storage.GDPRDeletionRepository = (*mocks.MockGDPRDeletionRepository)(nil)
	var _ storage.GDPRExportRepository = (*mocks.MockGDPRExportRepository)(nil)
}
