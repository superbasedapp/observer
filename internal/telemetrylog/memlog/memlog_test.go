package memlog_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
	"github.com/marmutapp/superbased-observer/internal/telemetrylog/logtest"
	"github.com/marmutapp/superbased-observer/internal/telemetrylog/memlog"
)

// TestConformance runs the shared adapter suite against memlog with real time.
func TestConformance(t *testing.T) {
	logtest.RunConformance(t, func(t *testing.T, cfg logtest.Config) telemetrylog.Log {
		return memlog.New(memlog.Options{
			MaxMessages:     cfg.MaxMessages,
			MaxMsgBytes:     cfg.MaxMsgBytes,
			DuplicateWindow: cfg.DuplicateWindow,
			// Now is nil: the suite uses real time (a broker cannot take an
			// injected clock, so the shared suite never does either).
		})
	})
}

func pushRecord(org, payload string) telemetrylog.Record {
	subj := telemetrylog.PushSubject(org)
	p := []byte(payload)
	return telemetrylog.Record{
		Org:        org,
		Subject:    subj,
		DedupID:    telemetrylog.DedupID(org, subj, p),
		PayloadVer: telemetrylog.PushPayloadVer,
		Payload:    p,
	}
}

// TestFailNextPublish pins the collector's WAL-before-ack 503 path (plan §6
// criterion 2): an armed Publish returns the chosen error exactly once.
func TestFailNextPublish(t *testing.T) {
	log := memlog.New(memlog.Options{})
	t.Cleanup(func() { _ = log.Close() })

	log.FailNextPublish(telemetrylog.ErrUnavailable)
	if _, err := log.Publish(context.Background(), pushRecord("acme", "a")); !errors.Is(err, telemetrylog.ErrUnavailable) {
		t.Fatalf("armed Publish = %v, want ErrUnavailable", err)
	}
	// The arming clears: the next Publish succeeds and stores the record.
	if _, err := log.Publish(context.Background(), pushRecord("acme", "a")); err != nil {
		t.Fatalf("subsequent Publish = %v, want nil", err)
	}
	st, err := log.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats = %v", err)
	}
	if st.Messages != 1 {
		t.Fatalf("Messages = %d, want 1 (the failed publish stored nothing)", st.Messages)
	}
}

// clock is a controllable clock for the injected-clock window test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestDuplicateWindowExpiryInjectedClock proves — without sleeping — that a
// duplicate published INSIDE the window is a no-op but the same content
// published AFTER the window lands as a new record (mirroring JetStream).
func TestDuplicateWindowExpiryInjectedClock(t *testing.T) {
	clk := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	log := memlog.New(memlog.Options{
		DuplicateWindow: 2 * time.Second,
		Now:             clk.now,
	})
	t.Cleanup(func() { _ = log.Close() })

	rec := pushRecord("acme", "same-body")

	first, err := log.Publish(context.Background(), rec)
	if err != nil || first.Duplicate {
		t.Fatalf("first publish = %+v, err %v, want stored non-duplicate", first, err)
	}
	// Still inside the window: a duplicate.
	clk.advance(1 * time.Second)
	inWin, err := log.Publish(context.Background(), rec)
	if err != nil || !inWin.Duplicate {
		t.Fatalf("in-window publish = %+v, err %v, want Duplicate=true", inWin, err)
	}
	// Past the window: a NEW record.
	clk.advance(2 * time.Second) // now 3s after the original store
	afterWin, err := log.Publish(context.Background(), rec)
	if err != nil {
		t.Fatalf("post-window publish err = %v", err)
	}
	if afterWin.Duplicate {
		t.Fatalf("post-window publish reported Duplicate; want a new record")
	}
	st, _ := log.Stats(context.Background())
	if st.Messages != 2 {
		t.Fatalf("Messages = %d, want 2 (in-window dup dropped, post-window stored)", st.Messages)
	}
	if afterWin.Sequence <= first.Sequence {
		t.Fatalf("post-window sequence %d not > original %d", afterWin.Sequence, first.Sequence)
	}
}

// TestClosedReturnsErrClosed pins that every call after Close reports ErrClosed.
func TestClosedReturnsErrClosed(t *testing.T) {
	log := memlog.New(memlog.Options{})
	if err := log.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil (idempotent)", err)
	}
	if _, err := log.Publish(context.Background(), pushRecord("acme", "a")); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Fatalf("Publish after Close = %v, want ErrClosed", err)
	}
	if _, err := log.Subscribe(context.Background(), telemetrylog.ConsumerSpec{Name: "x"}); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Fatalf("Subscribe after Close = %v, want ErrClosed", err)
	}
	if _, err := log.Stats(context.Background()); !errors.Is(err, telemetrylog.ErrClosed) {
		t.Fatalf("Stats after Close = %v, want ErrClosed", err)
	}
	if rep := log.Probe(context.Background()); rep.Healthy {
		t.Fatalf("Probe after Close = %+v, want Healthy=false", rep)
	}
}
