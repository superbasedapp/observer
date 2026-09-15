package natslog

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
)

func TestRequeueBypassesOriginalWindowButPreservesArchiveIdentity(t *testing.T) {
	log := newTestLog(t, Options{DuplicateWindow: time.Minute})
	consumer, err := log.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: "requeue-test", AckWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	record := rec("org", telemetrylog.PushSubject("org"), "original", `{"content":"body"}`, map[string]string{"user_id": "user", "pushed_at": "2026-09-09T00:00:00Z"})
	if _, err := log.Publish(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	first, err := consumer.Fetch(t.Context(), 1, time.Second)
	if err != nil || len(first) != 1 {
		t.Fatalf("first=%d err=%v", len(first), err)
	}
	if err := first[0].Term(t.Context(), "test parking"); err != nil {
		t.Fatal(err)
	}
	ack, err := Requeue(t.Context(), log.nc, log.opts.Stream, record, "attempt-one")
	if err != nil || ack.Duplicate || ack.Sequence != 2 {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	second, err := consumer.Fetch(t.Context(), 1, time.Second)
	if err != nil || len(second) != 1 {
		t.Fatalf("second=%d err=%v", len(second), err)
	}
	if !reflect.DeepEqual(second[0].Record(), record) {
		t.Fatalf("original identity/payload not preserved: %+v", second[0].Record())
	}
	if err := second[0].Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	duplicate, err := Requeue(t.Context(), log.nc, log.opts.Stream, record, "attempt-one")
	if !errors.Is(err, ErrRequeueSuppressed) || !duplicate.Duplicate {
		t.Fatalf("suppression=%+v err=%v", duplicate, err)
	}
	stats, err := log.Stats(t.Context())
	if err != nil || stats.Messages != 2 {
		t.Fatalf("messages=%d err=%v", stats.Messages, err)
	}
	if _, err := Requeue(t.Context(), log.nc, "wrong-stream", record, "attempt-two"); err == nil {
		t.Fatal("unexpected stream accepted")
	}
	if _, err := Requeue(t.Context(), nil, log.opts.Stream, record, "attempt-two"); err == nil {
		t.Fatal("nil connection accepted")
	}
	if _, err := Requeue(t.Context(), log.nc, log.opts.Stream, record, ""); err == nil {
		t.Fatal("empty attempt accepted")
	}
	bad := record
	bad.Org = "other"
	if _, err := Requeue(t.Context(), log.nc, log.opts.Stream, bad, "attempt-two"); err == nil {
		t.Fatal("foreign org accepted")
	}
}
