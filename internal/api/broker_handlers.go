package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// BrokerHandlers groups HTTP handlers for public broker token endpoints.
type BrokerHandlers struct {
	broker BrokerTokenService
}

// NewBrokerHandlers creates a new BrokerHandlers with the given BrokerTokenService.
func NewBrokerHandlers(broker BrokerTokenService) *BrokerHandlers {
	return &BrokerHandlers{broker: broker}
}

// Token handles POST /auth/broker/token.
// Authenticates the calling agent and issues a short-lived proxy token
// scoped to the requested target credential.
func (h *BrokerHandlers) Token(c *gin.Context) {
	var req BrokerTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	result, err := h.broker.IssueBrokerToken(c.Request.Context(), req.ClientID, req.ClientSecret, req.TargetName)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
