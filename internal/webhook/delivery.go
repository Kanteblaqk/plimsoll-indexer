package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/plimsoll-protocol/plimsoll-indexer/internal/store"
)

type subscriptionStore interface {
	ListWebhooks(context.Context) ([]store.Webhook, error)
}

// deliveryRecorder is optional so a read-only store can still be used to
// enumerate subscriptions; production stores record every attempt.
type deliveryRecorder interface {
	RecordWebhookDelivery(context.Context, store.WebhookDelivery) error
}

type Dispatcher struct {
	Store  subscriptionStore
	Codec  *SecretCodec
	Client *http.Client
	Now    func() time.Time
}

type TOMLChangedPayload struct {
	Event      string    `json:"event"`
	Issuer     string    `json:"issuer"`
	HomeDomain string    `json:"home_domain"`
	OldHash    string    `json:"old_hash"`
	NewHash    string    `json:"new_hash"`
	OccurredAt time.Time `json:"occurred_at"`
}

func NewDispatcher(db subscriptionStore, codec *SecretCodec) *Dispatcher {
	return &Dispatcher{
		Store: db,
		Codec: codec,
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Now: time.Now,
	}
}

func (d *Dispatcher) TOMLChanged(ctx context.Context, issuer, domain, oldHash, newHash string) error {
	webhooks, err := d.Store.ListWebhooks(ctx)
	if err != nil {
		return fmt.Errorf("list webhook subscriptions: %w", err)
	}
	now := d.Now().UTC()
	payload, err := json.Marshal(TOMLChangedPayload{
		Event:      "issuer_toml_changed",
		Issuer:     issuer,
		HomeDomain: domain,
		OldHash:    oldHash,
		NewHash:    newHash,
		OccurredAt: now,
	})
	if err != nil {
		return fmt.Errorf("encode TOML change webhook payload: %w", err)
	}

	var failures []error
	for _, w := range webhooks {
		if err := d.deliver(ctx, w, payload, "issuer_toml_changed"); err != nil {
			failures = append(failures, fmt.Errorf("deliver webhook %d: %w", w.ID, err))
		}
	}
	return errors.Join(failures...)
}

func (d *Dispatcher) deliver(ctx context.Context, w store.Webhook, payload []byte, event string) error {
	secret, err := d.Codec.Decrypt(w.SecretCiphertext)
	if err != nil {
		return err
	}
	if !VerifySecretHash(secret, w.SecretHash) {
		return fmt.Errorf("webhook secret hash mismatch")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Plimsoll-Signature-256", Sign(payload, secret))

	attemptedAt := d.Now().UTC()
	started := time.Now()
	resp, sendErr := d.Client.Do(req)
	statusCode := 0
	var deliveryErr error
	if sendErr != nil {
		deliveryErr = fmt.Errorf("send webhook request: %w", sendErr)
	} else {
		statusCode = resp.StatusCode
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		switch {
		case readErr != nil:
			deliveryErr = fmt.Errorf("read webhook response: %w", readErr)
		case statusCode < 200 || statusCode >= 300:
			deliveryErr = fmt.Errorf("webhook returned status %d", statusCode)
		}
	}

	// Latency covers the whole exchange, including reading the response body,
	// so it reflects how long the upstream endpoint really took.
	latency := time.Since(started).Milliseconds()
	if recorder, ok := d.Store.(deliveryRecorder); ok {
		record := store.WebhookDelivery{
			WebhookID:         w.ID,
			Event:             event,
			StatusCode:        statusCode,
			DeliveryLatencyMS: latency,
			AttemptedAt:       attemptedAt,
		}
		if deliveryErr != nil {
			record.Error = deliveryErr.Error()
		}
		if err := recorder.RecordWebhookDelivery(ctx, record); err != nil {
			deliveryErr = errors.Join(deliveryErr, fmt.Errorf("record webhook delivery: %w", err))
		}
	}
	return deliveryErr
}
