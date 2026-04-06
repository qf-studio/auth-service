package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock AdminWebhookService ---

type mockAdminWebhookService struct {
	listWebhooksFn   func(ctx context.Context, page, perPage int, activeOnly bool) (*api.AdminWebhookList, error)
	getWebhookFn     func(ctx context.Context, webhookID string) (*api.AdminWebhook, error)
	createWebhookFn  func(ctx context.Context, req *api.CreateWebhookRequest) (*api.AdminWebhookWithSecret, error)
	updateWebhookFn  func(ctx context.Context, webhookID string, req *api.UpdateWebhookRequest) (*api.AdminWebhook, error)
	deleteWebhookFn  func(ctx context.Context, webhookID string) error
	listDeliveriesFn func(ctx context.Context, webhookID string, page, perPage int) (*api.AdminWebhookDeliveryList, error)
	retryDeliveryFn  func(ctx context.Context, webhookID, deliveryID string) (*api.AdminWebhookDelivery, error)
	testWebhookFn    func(ctx context.Context, webhookID string, req *api.TestWebhookRequest) (*api.TestWebhookResponse, error)
}

func (m *mockAdminWebhookService) ListWebhooks(ctx context.Context, page, perPage int, activeOnly bool) (*api.AdminWebhookList, error) {
	if m.listWebhooksFn != nil {
		return m.listWebhooksFn(ctx, page, perPage, activeOnly)
	}
	return &api.AdminWebhookList{
		Webhooks: []api.AdminWebhook{{
			ID:           "wh1",
			URL:          "https://example.com/webhook",
			EventTypes:   []string{"admin_user_create"},
			Active:       true,
			FailureCount: 0,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminWebhookService) GetWebhook(ctx context.Context, webhookID string) (*api.AdminWebhook, error) {
	if m.getWebhookFn != nil {
		return m.getWebhookFn(ctx, webhookID)
	}
	return &api.AdminWebhook{
		ID:           webhookID,
		URL:          "https://example.com/webhook",
		EventTypes:   []string{"admin_user_create"},
		Active:       true,
		FailureCount: 0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}

func (m *mockAdminWebhookService) CreateWebhook(ctx context.Context, req *api.CreateWebhookRequest) (*api.AdminWebhookWithSecret, error) {
	if m.createWebhookFn != nil {
		return m.createWebhookFn(ctx, req)
	}
	return &api.AdminWebhookWithSecret{
		AdminWebhook: api.AdminWebhook{
			ID:           "new-webhook",
			URL:          req.URL,
			EventTypes:   req.EventTypes,
			Active:       true,
			FailureCount: 0,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		},
		Secret: "whsec_abcdef0123456789",
	}, nil
}

func (m *mockAdminWebhookService) UpdateWebhook(ctx context.Context, webhookID string, req *api.UpdateWebhookRequest) (*api.AdminWebhook, error) {
	if m.updateWebhookFn != nil {
		return m.updateWebhookFn(ctx, webhookID, req)
	}
	url := "https://example.com/webhook"
	if req.URL != nil {
		url = *req.URL
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	eventTypes := []string{"admin_user_create"}
	if req.EventTypes != nil {
		eventTypes = req.EventTypes
	}
	return &api.AdminWebhook{
		ID:           webhookID,
		URL:          url,
		EventTypes:   eventTypes,
		Active:       active,
		FailureCount: 0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}, nil
}

func (m *mockAdminWebhookService) DeleteWebhook(ctx context.Context, webhookID string) error {
	if m.deleteWebhookFn != nil {
		return m.deleteWebhookFn(ctx, webhookID)
	}
	return nil
}

func (m *mockAdminWebhookService) ListDeliveries(ctx context.Context, webhookID string, page, perPage int) (*api.AdminWebhookDeliveryList, error) {
	if m.listDeliveriesFn != nil {
		return m.listDeliveriesFn(ctx, webhookID, page, perPage)
	}
	return &api.AdminWebhookDeliveryList{
		Deliveries: []api.AdminWebhookDelivery{{
			ID:        "del1",
			WebhookID: webhookID,
			EventType: "admin_user_create",
			Payload:   `{"event_type":"admin_user_create"}`,
			Status:    "delivered",
			Attempt:   1,
			CreatedAt: time.Now(),
		}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminWebhookService) RetryDelivery(ctx context.Context, webhookID, deliveryID string) (*api.AdminWebhookDelivery, error) {
	if m.retryDeliveryFn != nil {
		return m.retryDeliveryFn(ctx, webhookID, deliveryID)
	}
	return &api.AdminWebhookDelivery{
		ID:        deliveryID,
		WebhookID: webhookID,
		EventType: "admin_user_create",
		Payload:   `{"event_type":"admin_user_create"}`,
		Status:    "delivered",
		Attempt:   2,
		CreatedAt: time.Now(),
	}, nil
}

func (m *mockAdminWebhookService) TestWebhook(ctx context.Context, webhookID string, req *api.TestWebhookRequest) (*api.TestWebhookResponse, error) {
	if m.testWebhookFn != nil {
		return m.testWebhookFn(ctx, webhookID, req)
	}
	code := 200
	return &api.TestWebhookResponse{
		DeliveryID:   "test-delivery-1",
		Status:       "delivered",
		ResponseCode: &code,
	}, nil
}

// --- Helper ---

func newAdminWebhookRouter(webhookSvc api.AdminWebhookService) *gin.Engine {
	svc := &api.AdminServices{Webhooks: webhookSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List Webhooks ---

func TestAdminListWebhooks_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodGet, "/admin/webhooks", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminWebhookList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Webhooks, 1)
}

func TestAdminListWebhooks_Pagination(t *testing.T) {
	svc := &mockAdminWebhookService{
		listWebhooksFn: func(_ context.Context, page, perPage int, activeOnly bool) (*api.AdminWebhookList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.False(t, activeOnly)
			return &api.AdminWebhookList{Webhooks: []api.AdminWebhook{}, Total: 50, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/webhooks?page=2&per_page=10", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminWebhookList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
}

func TestAdminListWebhooks_ActiveFilter(t *testing.T) {
	svc := &mockAdminWebhookService{
		listWebhooksFn: func(_ context.Context, page, perPage int, activeOnly bool) (*api.AdminWebhookList, error) {
			assert.True(t, activeOnly)
			return &api.AdminWebhookList{Webhooks: []api.AdminWebhook{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/webhooks?active=true", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListWebhooks_ServiceError(t *testing.T) {
	svc := &mockAdminWebhookService{
		listWebhooksFn: func(_ context.Context, _, _ int, _ bool) (*api.AdminWebhookList, error) {
			return nil, fmt.Errorf("list failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/webhooks", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Get Webhook ---

func TestAdminGetWebhook_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodGet, "/admin/webhooks/wh-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminWebhook
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "wh-1", resp.ID)
}

func TestAdminGetWebhook_NotFound(t *testing.T) {
	svc := &mockAdminWebhookService{
		getWebhookFn: func(_ context.Context, _ string) (*api.AdminWebhook, error) {
			return nil, fmt.Errorf("webhook not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/webhooks/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create Webhook ---

func TestAdminCreateWebhook_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	body := map[string]interface{}{
		"url":         "https://example.com/webhook",
		"event_types": []string{"admin_user_create", "admin_user_delete"},
	}
	w := doRequest(r, http.MethodPost, "/admin/webhooks", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminWebhookWithSecret
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "https://example.com/webhook", resp.URL)
	assert.NotEmpty(t, resp.Secret, "secret must be returned on create")
}

func TestAdminCreateWebhook_MissingURL(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	body := map[string]interface{}{
		"event_types": []string{"admin_user_create"},
	}
	w := doRequest(r, http.MethodPost, "/admin/webhooks", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateWebhook_MissingEventTypes(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	body := map[string]interface{}{
		"url": "https://example.com/webhook",
	}
	w := doRequest(r, http.MethodPost, "/admin/webhooks", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateWebhook_InvalidJSON(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodPost, "/admin/webhooks", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateWebhook_ServiceError(t *testing.T) {
	svc := &mockAdminWebhookService{
		createWebhookFn: func(_ context.Context, _ *api.CreateWebhookRequest) (*api.AdminWebhookWithSecret, error) {
			return nil, fmt.Errorf("create failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminWebhookRouter(svc)
	body := map[string]interface{}{
		"url":         "https://example.com/webhook",
		"event_types": []string{"admin_user_create"},
	}
	w := doRequest(r, http.MethodPost, "/admin/webhooks", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Update Webhook ---

func TestAdminUpdateWebhook_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	url := "https://new-url.com/webhook"
	body := map[string]interface{}{"url": url}
	w := doRequest(r, http.MethodPatch, "/admin/webhooks/wh-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminWebhook
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "https://new-url.com/webhook", resp.URL)
}

func TestAdminUpdateWebhook_NotFound(t *testing.T) {
	svc := &mockAdminWebhookService{
		updateWebhookFn: func(_ context.Context, _ string, _ *api.UpdateWebhookRequest) (*api.AdminWebhook, error) {
			return nil, fmt.Errorf("webhook not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminWebhookRouter(svc)
	body := map[string]interface{}{"url": "https://example.com"}
	w := doRequest(r, http.MethodPatch, "/admin/webhooks/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminUpdateWebhook_InvalidJSON(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodPatch, "/admin/webhooks/wh-1", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminUpdateWebhook_DisableWebhook(t *testing.T) {
	svc := &mockAdminWebhookService{
		updateWebhookFn: func(_ context.Context, webhookID string, req *api.UpdateWebhookRequest) (*api.AdminWebhook, error) {
			assert.Equal(t, "wh-1", webhookID)
			require.NotNil(t, req.Active)
			assert.False(t, *req.Active)
			return &api.AdminWebhook{
				ID:         webhookID,
				URL:        "https://example.com/webhook",
				EventTypes: []string{"admin_user_create"},
				Active:     false,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}, nil
		},
	}
	r := newAdminWebhookRouter(svc)
	body := map[string]interface{}{"active": false}
	w := doRequest(r, http.MethodPatch, "/admin/webhooks/wh-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminWebhook
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
}

// --- Delete Webhook ---

func TestAdminDeleteWebhook_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodDelete, "/admin/webhooks/wh-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteWebhook_NotFound(t *testing.T) {
	svc := &mockAdminWebhookService{
		deleteWebhookFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("webhook not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/webhooks/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- List Deliveries ---

func TestAdminListDeliveries_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodGet, "/admin/webhooks/wh-1/deliveries", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminWebhookDeliveryList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Deliveries, 1)
}

func TestAdminListDeliveries_NotFound(t *testing.T) {
	svc := &mockAdminWebhookService{
		listDeliveriesFn: func(_ context.Context, _ string, _, _ int) (*api.AdminWebhookDeliveryList, error) {
			return nil, fmt.Errorf("webhook not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/webhooks/nonexistent/deliveries", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Retry Delivery ---

func TestAdminRetryDelivery_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodPost, "/admin/webhooks/wh-1/deliveries/del-1/retry", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminWebhookDelivery
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "del-1", resp.ID)
	assert.Equal(t, 2, resp.Attempt)
}

func TestAdminRetryDelivery_WebhookNotFound(t *testing.T) {
	svc := &mockAdminWebhookService{
		retryDeliveryFn: func(_ context.Context, _, _ string) (*api.AdminWebhookDelivery, error) {
			return nil, fmt.Errorf("webhook not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodPost, "/admin/webhooks/nonexistent/deliveries/del-1/retry", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminRetryDelivery_DeliveryNotFound(t *testing.T) {
	svc := &mockAdminWebhookService{
		retryDeliveryFn: func(_ context.Context, _, _ string) (*api.AdminWebhookDelivery, error) {
			return nil, fmt.Errorf("delivery not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminWebhookRouter(svc)
	w := doRequest(r, http.MethodPost, "/admin/webhooks/wh-1/deliveries/nonexistent/retry", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Test Webhook ---

func TestAdminTestWebhook_Success(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	body := map[string]interface{}{
		"event_type": "admin_user_create",
	}
	w := doRequest(r, http.MethodPost, "/admin/webhooks/wh-1/test", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.TestWebhookResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "delivered", resp.Status)
	assert.NotEmpty(t, resp.DeliveryID)
}

func TestAdminTestWebhook_MissingEventType(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	body := map[string]interface{}{}
	w := doRequest(r, http.MethodPost, "/admin/webhooks/wh-1/test", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminTestWebhook_InvalidJSON(t *testing.T) {
	r := newAdminWebhookRouter(&mockAdminWebhookService{})
	w := doRequest(r, http.MethodPost, "/admin/webhooks/wh-1/test", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminTestWebhook_NotFound(t *testing.T) {
	svc := &mockAdminWebhookService{
		testWebhookFn: func(_ context.Context, _ string, _ *api.TestWebhookRequest) (*api.TestWebhookResponse, error) {
			return nil, fmt.Errorf("webhook not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminWebhookRouter(svc)
	body := map[string]interface{}{
		"event_type": "admin_user_create",
	}
	w := doRequest(r, http.MethodPost, "/admin/webhooks/nonexistent/test", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminTestWebhook_ServiceError(t *testing.T) {
	svc := &mockAdminWebhookService{
		testWebhookFn: func(_ context.Context, _ string, _ *api.TestWebhookRequest) (*api.TestWebhookResponse, error) {
			return nil, fmt.Errorf("test failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminWebhookRouter(svc)
	body := map[string]interface{}{
		"event_type": "admin_user_create",
	}
	w := doRequest(r, http.MethodPost, "/admin/webhooks/wh-1/test", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
