//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/store"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
)

// cloudsession_otelloop_serve.go is the receiver half of the in-sandbox
// loopback route (lane CA-C7): the generic receiver (internal/ingest/otlp)
// bound to a loopback address ONLY, in front of the same vendor ingest glue
// the node's own receiver uses (newOTLPIngest), writing into the sandbox's
// database. Differences from the node's receiver, all deliberate:
//   - loopback only and never token-gated: AllowNonLoopback stays false, so
//     the receiver refuses any other bind (ErrNonLoopback);
//   - no proxy route: a cloud sandbox never runs Observer's proxy (the terms
//     review, grounding/terms-review-claude-code-proxy-2026-11-01.md), so
//     the transcript rule alone decides what the export may write;
//   - a bounded life: it stops after an idle period and after a maximum
//     lifetime, and on SIGTERM/SIGINT.
// An org-enrolled node is refused exactly like the flush refuses it, so a
// stray marker variable on a developer machine cannot start it there.

// runOTelLoopbackServe serves until a signal, the idle bound or the lifetime
// bound. Its log goes to otel-receiver.log in the cloud-session state
// directory (ensure starts it with stdio on /dev/null).
func runOTelLoopbackServe(ctx context.Context, o otelLoopServeOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	stateDir, _, err := openCloudSessionState(ctx, o.ConfigPath)
	if err != nil {
		return err
	}
	cfg, database, cleanup, err := loadConfigAndDB(ctx, o.ConfigPath)
	if err != nil {
		return err
	}
	defer cleanup()

	logFile, err := os.OpenFile(filepath.Join(stateDir, "otel-receiver.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("otel-receiver: log: %w", err)
	}
	defer func() { _ = logFile.Close() }()
	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, o.MaxLifetime)
	defer cancel()

	ing := newOTLPIngest(store.New(database), logger, cfg.Ingest.OTel.CapturesContent(), cfg.Ingest.OTel.MaxContentBytes(),
		enabledAdapterSet(cfg.Observer.Watch.EnabledAdapters))
	go ing.runGenTimingRetry(ctx)

	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	logs := func(c context.Context, req *collogspb.ExportLogsServiceRequest) error {
		last.Store(time.Now().UnixNano())
		return ing.logs(c, req)
	}
	recv, err := otlpingest.New(otlpingest.Options{
		HTTPAddr: o.Addr, Handler: logs, TraceHandler: ing.traces(nil), Logger: logger,
	})
	if err != nil {
		logger.Warn("otel-receiver: not started", "addr", o.Addr, "err", err)
		return fmt.Errorf("otel-receiver: %w", err)
	}
	recv.Start()
	logger.Info("otel-receiver: listening", "addr", recv.HTTPAddr(), "idle", o.Idle, "max_lifetime", o.MaxLifetime)

	tick := time.NewTicker(otelLoopIdleCheck(o.Idle))
	defer tick.Stop()
	reason := "stopped"
loop:
	for {
		select {
		case <-ctx.Done():
			reason = context.Cause(ctx).Error()
			break loop
		case <-tick.C:
			if o.Idle > 0 && time.Since(time.Unix(0, last.Load())) >= o.Idle {
				reason = "idle"
				break loop
			}
		}
	}
	sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer scancel()
	_ = recv.Shutdown(sctx)
	logger.Info("otel-receiver: stopped", "reason", reason)
	return nil
}

// otelLoopIdleCheck is how often the idle bound is checked.
func otelLoopIdleCheck(idle time.Duration) time.Duration {
	if idle > 0 && idle < time.Minute {
		return idle / 2
	}
	return time.Minute
}
