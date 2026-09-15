package natslog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

const headerOriginalDedupID = "Sbo-Original-Dedup-Id"

// ErrRequeueSuppressed means the broker recognized an already-used attempt ID.
// It is NOT evidence of a newly queued record; callers must not clear quarantine.
var ErrRequeueSuppressed = errors.New("natslog: requeue attempt suppressed by duplicate window")

// Requeue publishes an explicitly retried record to an EXISTING stream, using a
// distinct broker message ID but preserving its original archival identity.
// A new attemptID bypasses the original record's duplicate window. Reusing an
// attemptID is detectable and never reported as a fresh successful requeue.
// This additive adapter API does not change the fixed telemetrylog.Log seam.
func Requeue(ctx context.Context, nc *nats.Conn, stream string, record telemetrylog.Record, attemptID string) (telemetrylog.PubResult, error) {
	if nc == nil || strings.TrimSpace(stream) == "" || strings.TrimSpace(attemptID) == "" || len(attemptID) > 128 {
		return telemetrylog.PubResult{}, fmt.Errorf("natslog.Requeue: connection, stream and bounded attempt ID required")
	}
	if err := telemetrylog.ValidateRecord(record); err != nil {
		return telemetrylog.PubResult{}, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return telemetrylog.PubResult{}, fmt.Errorf("natslog.Requeue: JetStream context: %w", err)
	}
	identity, err := json.Marshal([]string{"requeue-v1", record.Org, record.Subject, record.DedupID, attemptID})
	if err != nil {
		return telemetrylog.PubResult{}, fmt.Errorf("natslog.Requeue: identity: %w", err)
	}
	message := nats.NewMsg(record.Subject)
	message.Data = record.Payload
	message.Header.Set(headerMsgID, telemetrylog.DedupID(record.Org, record.Subject, identity))
	message.Header.Set(headerOriginalDedupID, record.DedupID)
	message.Header.Set(headerOrg, record.Org)
	message.Header.Set(headerPayloadVer, strconv.Itoa(record.PayloadVer))
	for key, value := range record.Attrs {
		message.Header.Set(headerAttrPrefix+key, value)
	}
	ack, err := js.PublishMsg(ctx, message, jetstream.WithExpectStream(stream))
	if err != nil {
		return telemetrylog.PubResult{}, fmt.Errorf("natslog.Requeue: %w", classifyPublishErr(err))
	}
	result := telemetrylog.PubResult{Sequence: ack.Sequence, Duplicate: ack.Duplicate}
	if ack.Duplicate {
		return result, ErrRequeueSuppressed
	}
	return result, nil
}
