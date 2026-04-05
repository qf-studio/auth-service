package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HTTPSender implements EmailSender by calling the email-service REST API.
// It sends a POST /send-email request with an API key in the Authorization header.
type HTTPSender struct {
	client        *http.Client
	serviceURL    string // base URL, e.g. "https://email.internal"
	apiKey        string
	senderAddress string
}

// NewHTTPSender constructs an HTTPSender.
//
//   - serviceURL: base URL of the email service (no trailing slash)
//   - apiKey: bearer token for the Authorization header
//   - senderAddress: the From address included in every outgoing message
//   - client: HTTP client to use; pass nil to get http.DefaultClient
func NewHTTPSender(serviceURL, apiKey, senderAddress string, client *http.Client) *HTTPSender {
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTPSender{
		client:        client,
		serviceURL:    serviceURL,
		apiKey:        apiKey,
		senderAddress: senderAddress,
	}
}

// sendEmailRequest mirrors the email-service /send-email JSON body.
type sendEmailRequest struct {
	From      string   `json:"from"`
	To        []string `json:"to"`
	Subject   string   `json:"subject"`
	Body      string   `json:"body"`
	Transport string   `json:"transport"`
}

// Send delivers msg via POST {serviceURL}/send-email.
// A non-2xx status code is treated as an error.
func (s *HTTPSender) Send(ctx context.Context, msg Message) error {
	payload := sendEmailRequest{
		From:      s.senderAddress,
		To:        []string{msg.To},
		Subject:   msg.Subject,
		Body:      msg.Body,
		Transport: "default",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("email: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serviceURL+"/send-email", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("email: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("email: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("email: service returned %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
