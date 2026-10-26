package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
)

// --- In-memory test repositories ---

type memWebhookRepo struct {
	webhooks []*domain.Webhook
}

func (r *memWebhookRepo) List(_ context.Context, _ uuid.UUID, limit, offset int, _ bool) ([]*domain.Webhook, int, error) {
	total := len(r.webhooks)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return r.webhooks[offset:end], total, nil
}

func (r *memWebhookRepo) FindByID(_ context.Context, _ uuid.UUID, id uuid.UUID) (*domain.Webhook, error) {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			return wh, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (r *memWebhookRepo) FindActiveByEventType(_ context.Context, _ uuid.UUID, eventType string) ([]*domain.Webhook, error) {
	var result []*domain.Webhook
	for _, wh := range r.webhooks {
		if !wh.Active {
			continue
		}
		for _, et := range wh.EventTypes {
			if et == eventType {
				result = append(result, wh)
				break
			}
		}
	}
	return result, nil
}

func (r *memWebhookRepo) Create(_ context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	r.webhooks = append(r.webhooks, wh)
	return wh, nil
}

func (r *memWebhookRepo) Update(_ context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	for i, existing := range r.webhooks {
		if existing.ID == wh.ID {
			r.webhooks[i] = wh
			return wh, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (r *memWebhookRepo) Delete(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for i, wh := range r.webhooks {
		if wh.ID == id {
			r.webhooks = append(r.webhooks[:i], r.webhooks[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found")
}

func (r *memWebhookRepo) IncrementFailureCount(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			wh.FailureCount++
			return nil
		}
	}
	return nil
}

func (r *memWebhookRepo) ResetFailureCount(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			wh.FailureCount = 0
			return nil
		}
	}
	return nil
}

func (r *memWebhookRepo) Disable(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			wh.Active = false
			return nil
		}
	}
	return nil
}

type memDeliveryRepo struct {
	deliveries []*domain.WebhookDelivery
}

func (r *memDeliveryRepo) List(_ context.Context, _ uuid.UUID, webhookID uuid.UUID, limit, offset int) ([]*domain.WebhookDelivery, int, error) {
	var filtered []*domain.WebhookDelivery
	for _, d := range r.deliveries {
		if d.WebhookID == webhookID {
			filtered = append(filtered, d)
		}
	}
	total := len(filtered)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return filtered[offset:end], total, nil
}

func (r *memDeliveryRepo) FindByID(_ context.Context, _ uuid.UUID, id uuid.UUID) (*domain.WebhookDelivery, error) {
	for _, d := range r.deliveries {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (r *memDeliveryRepo) Create(_ context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	r.deliveries = append(r.deliveries, d)
	return d, nil
}

func (r *memDeliveryRepo) UpdateStatus(_ context.Context, _ uuid.UUID, id uuid.UUID, status string, responseCode *int, responseBody *string, deliveredAt *time.Time) error {
	for _, d := range r.deliveries {
		if d.ID == id {
			d.Status = status
			d.ResponseCode = responseCode
			d.ResponseBody = responseBody
			d.DeliveredAt = deliveredAt
			return nil
		}
	}
	return nil
}

func (r *memDeliveryRepo) FindPendingRetries(_ context.Context, _ uuid.UUID, _ time.Time, _ int) ([]*domain.WebhookDelivery, error) {
	return nil, nil
}

// trustLoopbackServer lets d talk to a loopback httptest TLS server: it drops
// the public-address dial filter (which would refuse 127.0.0.1) but keeps the
// production redirect policy, and trusts the server's certificate.
func trustLoopbackServer(d *Dispatcher, ts *httptest.Server) {
	d.httpClient = newHTTPClient(nil, nil)
	d.httpClient.Transport.(*http.Transport).TLSClientConfig = ts.Client().Transport.(*http.Transport).TLSClientConfig
}

// --- Tests ---

func TestDeliverSingle_Success(t *testing.T) {
	var called atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)

		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get(signatureHeader))
		assert.Equal(t, "test_event", r.Header.Get(eventTypeHeader))
		assert.NotEmpty(t, r.Header.Get(deliveryIDHeader))

		var p Payload
		require.NoError(t, json.NewDecoder(r.Body).Decode(&p))
		assert.Equal(t, "test_event", p.EventType)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	whRepo := &memWebhookRepo{}
	delRepo := &memDeliveryRepo{}
	logger := zap.NewNop()
	d := NewDispatcher(whRepo, delRepo, logger)
	trustLoopbackServer(d, ts)
	defer func() { _ = d.Close() }()

	wh := &domain.Webhook{
		ID:         uuid.New(),
		URL:        ts.URL,
		SecretHash: "test-secret",
		EventTypes: []string{"test_event"},
		Active:     true,
	}

	payload := Payload{
		ID:        uuid.New().String(),
		EventType: "test_event",
		Timestamp: time.Now().UTC(),
		Data:      map[string]string{"key": "value"},
	}

	delivery, err := d.DeliverSingle(context.Background(), wh, payload)
	require.NoError(t, err)

	assert.Equal(t, int32(1), called.Load())
	assert.Equal(t, domain.WebhookDeliveryStatusDelivered, delivery.Status)
	assert.NotNil(t, delivery.ResponseCode)
	assert.Equal(t, 200, *delivery.ResponseCode)
	assert.NotNil(t, delivery.DeliveredAt)
}

func TestDeliverSingle_ServerError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer ts.Close()

	whRepo := &memWebhookRepo{}
	delRepo := &memDeliveryRepo{}
	logger := zap.NewNop()
	d := NewDispatcher(whRepo, delRepo, logger)
	trustLoopbackServer(d, ts)
	defer func() { _ = d.Close() }()

	wh := &domain.Webhook{
		ID:         uuid.New(),
		URL:        ts.URL,
		SecretHash: "test-secret",
		EventTypes: []string{"test_event"},
		Active:     true,
	}

	payload := Payload{
		ID:        uuid.New().String(),
		EventType: "test_event",
		Timestamp: time.Now().UTC(),
	}

	delivery, err := d.DeliverSingle(context.Background(), wh, payload)
	require.Error(t, err)
	require.NotNil(t, delivery)
	assert.Equal(t, 500, *delivery.ResponseCode)
}

func TestDispatcher_NameAndClose(t *testing.T) {
	d := NewDispatcher(&memWebhookRepo{}, &memDeliveryRepo{}, zap.NewNop())
	assert.Equal(t, "webhook-dispatcher", d.Name())
	require.NoError(t, d.Close())
}

func TestHMACSignature_CoversTimestamp(t *testing.T) {
	var sig, tsHeader string
	var gotBody []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get(signatureHeader)
		tsHeader = r.Header.Get(timestampHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := NewDispatcher(&memWebhookRepo{}, &memDeliveryRepo{}, zap.NewNop())
	defer func() { _ = d.Close() }()
	trustLoopbackServer(d, ts)
	fixed := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return fixed }

	wh := &domain.Webhook{ID: uuid.New(), URL: ts.URL, SecretHash: "my-signing-key", Active: true}
	payload := Payload{ID: "test-id", EventType: "test", Timestamp: fixed}

	_, err := d.DeliverSingle(context.Background(), wh, payload)
	require.NoError(t, err)

	wantTS := strconv.FormatInt(fixed.Unix(), 10)
	assert.Equal(t, wantTS, tsHeader)

	mac := hmac.New(sha256.New, []byte("my-signing-key"))
	mac.Write([]byte(wantTS + "." + string(gotBody)))
	assert.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), sig)

	// Same body with a different timestamp must produce a different signature.
	assert.NotEqual(t, sig, signPayload("my-signing-key", "1", gotBody))
	// A body-only signature (the old scheme) must no longer verify.
	legacy := hmac.New(sha256.New, []byte("my-signing-key"))
	legacy.Write(gotBody)
	assert.NotEqual(t, "sha256="+hex.EncodeToString(legacy.Sum(nil)), sig)
}

func TestDeliverSingle_RedirectNotFollowed(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	d := NewDispatcher(&memWebhookRepo{}, &memDeliveryRepo{}, zap.NewNop())
	defer func() { _ = d.Close() }()
	trustLoopbackServer(d, redirector)

	wh := &domain.Webhook{ID: uuid.New(), URL: redirector.URL, SecretHash: "k", Active: true}
	delivery, err := d.DeliverSingle(context.Background(), wh, Payload{ID: "id", EventType: "test"})

	require.Error(t, err)
	require.NotNil(t, delivery)
	require.NotNil(t, delivery.ResponseCode)
	assert.Equal(t, http.StatusFound, *delivery.ResponseCode)
	assert.Zero(t, targetHits.Load(), "redirect must not be followed")
}

func TestDeliverSingle_ResponseBodyNotStored(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secret-internal-data"))
	}))
	defer ts.Close()

	delRepo := &memDeliveryRepo{}
	d := NewDispatcher(&memWebhookRepo{}, delRepo, zap.NewNop())
	defer func() { _ = d.Close() }()
	trustLoopbackServer(d, ts)

	wh := &domain.Webhook{ID: uuid.New(), URL: ts.URL, Active: true}
	delivery, err := d.DeliverSingle(context.Background(), wh, Payload{ID: "id", EventType: "test"})
	require.NoError(t, err)

	require.NotNil(t, delivery.ResponseBody)
	assert.Empty(t, *delivery.ResponseBody)
	require.Len(t, delRepo.deliveries, 1)
	require.NotNil(t, delRepo.deliveries[0].ResponseBody)
	assert.Empty(t, *delRepo.deliveries[0].ResponseBody)
}

// fakeResolver returns a net.Resolver whose every lookup is answered by a
// local UDP DNS server replying with the given A record.
func fakeResolver(t *testing.T, ip net.IP) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 12 {
				continue
			}
			// Echo header + question, flag as response; answer A queries only
			// (other types, e.g. AAAA, get an empty NOERROR answer).
			qEnd := 12
			for qEnd < n && buf[qEnd] != 0 {
				qEnd += int(buf[qEnd]) + 1
			}
			qEnd += 5 // root label + QTYPE + QCLASS
			if qEnd > n {
				continue
			}
			resp := append([]byte{}, buf[:qEnd]...)
			resp[2], resp[3] = 0x81, 0x80
			resp[6], resp[7] = 0, 0
			resp[8], resp[9], resp[10], resp[11] = 0, 0, 0, 0
			if buf[qEnd-4] == 0 && buf[qEnd-3] == 1 {
				resp[7] = 1
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, ip.To4()...)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
}

func TestDialer_RefusesHostnameResolvingToLoopback(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	_, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)

	d := NewDispatcher(&memWebhookRepo{}, &memDeliveryRepo{}, zap.NewNop())
	defer func() { _ = d.Close() }()
	// Production dial filter, but with a resolver pointing the name at 127.0.0.1.
	d.httpClient = newHTTPClient(fakeResolver(t, net.ParseIP("127.0.0.1")), controlPublicOnly)

	wh := &domain.Webhook{ID: uuid.New(), URL: "https://rebind.example.test:" + port, Active: true}
	delivery, err := d.DeliverSingle(context.Background(), wh, Payload{ID: "id", EventType: "test"})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBlockedAddress)
	assert.Nil(t, delivery.ResponseCode)
	assert.Zero(t, hits.Load(), "connection must be refused before reaching the server")
}

func TestDialer_AllowsHostnameResolvingToPublicAddress(t *testing.T) {
	// The filter itself is exercised by TestIsBlockedIP; here we only check the
	// Control func accepts a public literal.
	require.NoError(t, controlPublicOnly("tcp4", "93.184.216.34:443", nil))
	require.ErrorIs(t, controlPublicOnly("tcp4", "127.0.0.1:443", nil), ErrBlockedAddress)
	require.ErrorIs(t, controlPublicOnly("tcp6", "[::1]:443", nil), ErrBlockedAddress)
}
