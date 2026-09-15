package natslog

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

// JetStream API error codes the adapter classifies. The jetstream client does
// not export named constants for these, so we pin the numbers (they are stable
// wire values from the nats-server error table).
const (
	// codeAccountResources is "resource limits exceeded for account" (10002).
	codeAccountResources jetstream.ErrorCode = 10002
	// codeStorageResources is "insufficient storage resources available"
	// (10047), including a stream reservation above the broker's storage cap.
	codeStorageResources jetstream.ErrorCode = 10047
	// codeMessageExceedsMax is "message size exceeds maximum allowed" (10054),
	// the stream MaxMsgSize rejection.
	codeMessageExceedsMax jetstream.ErrorCode = 10054
	// codeStreamStoreFailed is the generic store-failed code (10077) the server
	// returns for a Discard:New stream at capacity ("maximum messages
	// exceeded" / "maximum bytes exceeded").
	codeStreamStoreFailed jetstream.ErrorCode = 10077
)

// streamProvisionErr adds an actionable capacity hint without changing the
// requested retention cap or losing the broker's structured failure cause.
// This is the REACTIVE catch: the broker itself refused CreateStream/
// UpdateStream (error 10047) because the requested MaxBytes reservation does
// not fit its storage. See preflightCapacityErr for the PROACTIVE half of the
// same fix, which catches the identical misconfiguration before ever
// attempting to provision the stream.
func streamProvisionErr(err error, maxBytes int64) error {
	if ae := apiErr(err); ae != nil && ae.ErrorCode == codeStorageResources {
		return fmt.Errorf("natslog: cannot provision stream with requested MaxBytes=%d bytes (%.2f GiB); configure MaxBytes to fit available broker/account storage or increase broker storage capacity: %w",
			maxBytes, float64(maxBytes)/(1<<30), err)
	}
	return err
}

// preflightCapacityErr checks maxBytes against the broker's own advertised
// JetStream account storage limit (js.AccountInfo, Limits.MaxStore) BEFORE
// ensureStream ever attempts to create or update the stream — the incident
// this closes (plan O4's 250 GiB default stream cap against a 35 GB broker,
// JetStream error 10047) previously surfaced only reactively, on the first
// CreateStream/UpdateStream call, via streamProvisionErr above. Checking
// first means the same actionable message is available at connect time, the
// moment an operator can most easily act on it.
//
// This is deliberately FAIL-OPEN and best-effort, never a new hard
// dependency on the account-info API: maxBytes <= 0 (unlimited requested), an
// AccountInfo call that errors (older broker, permissions, transient
// failure), or a broker-advertised MaxStore <= 0 (unlimited, or the field is
// simply unset) all return nil and let ensureStream proceed — its 10047
// handling remains the authoritative backstop regardless.
func preflightCapacityErr(ctx context.Context, js jetstream.JetStream, maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}
	info, err := js.AccountInfo(ctx)
	if err != nil {
		return nil
	}
	maxStore := info.Limits.MaxStore
	if maxStore <= 0 || maxBytes <= maxStore {
		return nil
	}
	return fmt.Errorf("natslog: cannot provision stream with requested MaxBytes=%d bytes (%.2f GiB); the broker advertises only %d bytes (%.2f GiB) of JetStream account storage; configure MaxBytes to fit available broker/account storage or increase broker storage capacity",
		maxBytes, float64(maxBytes)/(1<<30), maxStore, float64(maxStore)/(1<<30))
}

// classifyPublishErr maps a Publish/PublishMsg failure onto a telemetrylog
// sentinel, or returns err unchanged when nothing matches (the caller wraps).
func classifyPublishErr(err error) error {
	switch {
	case isTooLarge(err):
		return telemetrylog.ErrTooLarge
	case isFull(err):
		return telemetrylog.ErrFull
	case isUnavailable(err):
		return telemetrylog.ErrUnavailable
	default:
		return err
	}
}

// mapTransportErr maps a Subscribe/Fetch/Stats/Info failure onto
// ErrUnavailable when it is a connection-level failure, else returns it
// unchanged. Capacity/size codes never reach these paths.
func mapTransportErr(err error) error {
	if isUnavailable(err) {
		return telemetrylog.ErrUnavailable
	}
	return err
}

// isTooLarge reports whether err is a per-record size rejection.
func isTooLarge(err error) bool {
	if errors.Is(err, nats.ErrMaxPayload) || errors.Is(err, jetstream.ErrMaxBytesExceeded) {
		return true
	}
	if ae := apiErr(err); ae != nil && ae.ErrorCode == codeMessageExceedsMax {
		return true
	}
	return false
}

// isFull reports whether err is a stream-at-capacity (Discard:New) rejection.
func isFull(err error) bool {
	if ae := apiErr(err); ae != nil {
		switch ae.ErrorCode {
		case codeStreamStoreFailed, codeAccountResources:
			return true
		}
	}
	// Fallback on the store's own message text, in case a build surfaces the
	// error without the structured APIError.
	s := err.Error()
	return strings.Contains(s, "maximum messages exceeded") ||
		strings.Contains(s, "maximum bytes exceeded") ||
		strings.Contains(s, "resource limits exceeded")
}

// isUnavailable reports whether err is a connection-level / timeout failure.
func isUnavailable(err error) bool {
	return errors.Is(err, nats.ErrNoResponders) ||
		errors.Is(err, nats.ErrConnectionClosed) ||
		errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrNoServers) ||
		errors.Is(err, jetstream.ErrNoStreamResponse) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}

// apiErr extracts a JetStream *APIError from err, or nil when there is none.
func apiErr(err error) *jetstream.APIError {
	var jsErr jetstream.JetStreamError
	if errors.As(err, &jsErr) {
		if ae := jsErr.APIError(); ae != nil {
			return ae
		}
	}
	var ae *jetstream.APIError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}
