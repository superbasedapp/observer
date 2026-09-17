package natslog_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
	"github.com/marmutapp/superbased-observer/internal/telemetrylog/logtest"
	"github.com/marmutapp/superbased-observer/internal/telemetrylog/natslog"
)

// TestNatslogConformance runs the shared log conformance suite (the one every
// adapter must pass, plan §4.1) against an embedded JetStream server in a
// per-sub-test temp dir.
func TestNatslogConformance(t *testing.T) {
	logtest.RunConformance(t, func(t *testing.T, cfg logtest.Config) telemetrylog.Log {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// EmbeddedTestOptions pins the small, explicit test-broker footprint;
		// the 10 GiB production MaxBytes default cannot be backed by a small CI
		// runner's disk and the broker refuses the stream outright.
		l, err := natslog.Embedded(ctx, t.TempDir(), natslog.EmbeddedTestOptions(natslog.Options{
			MaxMessages:     int64(cfg.MaxMessages),
			MaxMsgBytes:     int32(cfg.MaxMsgBytes),
			DuplicateWindow: cfg.DuplicateWindow,
			MaxDeliver:      cfg.MaxDeliver,
			AckWait:         cfg.AckWait,
			MaxAge:          cfg.DuplicateWindow * 4,
		}))
		if err != nil {
			t.Fatalf("natslog.Embedded: %v", err)
		}
		return l
	})
}
