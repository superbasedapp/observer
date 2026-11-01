//go:build !sbo_omit_ingest_otlp

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// otlp_ingest.go is the on side of the vendor OTLP ingest wiring (component
// ingest.otlp, modular packaging plan 5.1, lane MP-L1C). The generic
// receiver (internal/ingest/otlp) is core (ruling D-436): it also serves
// Plane A traces. This file owns what the component adds on top of it: the
// vendor mapping table (internal/otlpvendor) and the logs handler.
// otlp_ingest_omit.go is the off side.

// wireVendorOTLPIngest returns the receiver's logs handler and the trace
// handler that routes claimed vendor resources to the ingest and passes the
// rest to planeA. start.go's otlp-receiver calls it when [ingest.otel] is on.
//
// ctx bounds the background retry of export generation timings that arrived
// before their transcript rows (otlp_gentiming.go).
func wireVendorOTLPIngest(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger, planeA otlpingest.TraceHandler) (otlpingest.Handler, otlpingest.TraceHandler) {
	// T-536: a tool whose persisted proxy route is active has its token rows
	// owned by the proxy. REVIEW-4 P4-18: only when this node serves that
	// proxy. cfg here is the raw config the receiver reloads, so
	// [proxy].enabled alone would still say yes in a build without
	// capture.proxy, or with it inactive, and the export's token rows would
	// be dropped with no proxy row to hold them.
	serving := proxyServingReason(cfg, componentSnapshotForConfig(cfg).Active("capture.proxy")) == ""
	ing := newOTLPIngest(store.New(database), logger, cfg.Ingest.OTel.CapturesContent(), cfg.Ingest.OTel.MaxContentBytes(),
		enabledAdapterSet(cfg.Observer.Watch.EnabledAdapters)).
		withProxyRoutes(newProxyRouteResolver(serving, userHomeOrEmpty()).Routed)
	go ing.runGenTimingRetry(ctx)
	return ing.logs, ing.traces(planeA)
}

// otlpIngest is the native-telemetry ingest glue (Plane B): it maps an AI
// tool's own OpenTelemetry export through the vendor-agnostic table in
// internal/otlpvendor and writes the result through the existing store
// seams. It is the single seam between the schema-blind network receiver
// (internal/ingest/otlp) and the store. A PERMANENT per-row write error is
// logged and skipped so one poison record never fails the whole export. A
// TRANSIENT one (lock contention, a cancelled or timed-out write) is returned
// wrapped in otlpingest.ErrRetryLater, which the receiver answers with the
// OTLP-retryable status, so the exporter resends the batch instead of
// dropping it (P3-10). Every write here is idempotent on redelivery: turns
// upsert by request id, tool calls by (source_file, source_event_id), content
// by its hash key, and sessions are insert-only.
//
// One owner per row (CLAUDE.md module rule 4): what a vendor's export may
// write while the tool's own transcript capture is also active is decided
// by otlpvendor.Admit, never here.
type otlpIngest struct {
	st     *store.Store
	logger *slog.Logger
	// captureContent / contentMaxBytes are [ingest.otel].content_capture and
	// .content_max_bytes (config.IngestOTelConfig).
	captureContent  bool
	contentMaxBytes int
	// transcriptCapture reports whether the tool's own transcript adapter
	// is enabled on this node ([observer.watch].enabled_adapters).
	transcriptCapture func(tool string) bool
	// proxyRouted reports whether the tool's PERSISTED proxy route is
	// active on this node (proxyRouteResolver.Routed); nil means never. A
	// turn whose export carries the launcher's route marker counts as
	// proxied regardless (T-536).
	proxyRouted func(tool string) bool
	scrubber    *scrub.Scrubber
	// genPending parks export generation timings whose transcript row is
	// not ingested yet (otlp_gentiming.go); clock is time.Now outside tests.
	genPending genTimingPending
	clock      func() time.Time
	// warned remembers the one-time warnings (an unmapped service.name, a
	// refused team-grain vendor) so a chatty exporter does not flood the log.
	warned sync.Map
}

// newOTLPIngest builds the ingest glue. transcriptCapture nil means every
// tool's transcript capture is treated as active (the conservative default:
// only the dedup-safe kinds land).
func newOTLPIngest(st *store.Store, logger *slog.Logger, captureContent bool, contentMaxBytes int, transcriptCapture func(string) bool) *otlpIngest {
	if transcriptCapture == nil {
		transcriptCapture = func(string) bool { return true }
	}
	return &otlpIngest{
		st: st, logger: logger, captureContent: captureContent, contentMaxBytes: contentMaxBytes,
		transcriptCapture: transcriptCapture, scrubber: scrub.New(), clock: time.Now,
	}
}

// withProxyRoutes sets the persisted-route predicate (T-536) and returns o.
func (o *otlpIngest) withProxyRoutes(routed func(tool string) bool) *otlpIngest {
	o.proxyRouted = routed
	return o
}

// otlpLogsHandler is the logs handler with every transcript capture treated
// as active (the pre-T-475 signature, kept for its callers and tests).
//
// contentMaxBytes bounds a single otel_content row's stored Content (see
// ingestContent); callers pass config.IngestOTelConfig.MaxContentBytes().
func otlpLogsHandler(st *store.Store, logger *slog.Logger, captureContent bool, contentMaxBytes int) otlpingest.Handler {
	return newOTLPIngest(st, logger, captureContent, contentMaxBytes, nil).logs
}

// enabledAdapterSet turns the watcher allow-list into a transcriptCapture
// predicate.
func enabledAdapterSet(enabled []string) func(string) bool {
	set := make(map[string]bool, len(enabled))
	for _, a := range enabled {
		set[a] = true
	}
	return func(tool string) bool { return set[tool] }
}

// logs ingests one OTLP logs export.
func (o *otlpIngest) logs(ctx context.Context, req *collogspb.ExportLogsServiceRequest) error {
	res := otlpvendor.ParseLogs(req)
	if res.Skipped > 0 {
		o.logger.Warn("otlp ingest: skipped api_request events missing request_id", "count", res.Skipped)
	}
	return o.apply(ctx, res)
}

// traces returns the trace handler: spans from a resource a mapping row
// claims are Plane B and are mapped here; every other resource (an
// application's own GenAI spans, Observer's echo) goes to the Plane A
// handler unchanged when one is configured. The two planes never share a
// resource.
func (o *otlpIngest) traces(planeA otlpingest.TraceHandler) otlpingest.TraceHandler {
	return func(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
		mine, rest := splitClaimedTraces(req)
		var err error
		if mine != nil {
			err = o.apply(ctx, otlpvendor.ParseSpans(mine))
		}
		if rest != nil && planeA != nil {
			err = errors.Join(err, planeA(ctx, rest))
		}
		return err
	}
}

// splitClaimedTraces partitions a trace export by resource: resources whose
// service.name a mapping row claims (and that are not Observer's own echo)
// versus everything else. Either side is nil when empty.
func splitClaimedTraces(req *coltracepb.ExportTraceServiceRequest) (mine, rest *coltracepb.ExportTraceServiceRequest) {
	for _, rs := range req.GetResourceSpans() {
		attrs := rs.GetResource().GetAttributes()
		svc := ""
		for _, kv := range attrs {
			if kv.GetKey() == "service.name" {
				svc = kv.GetValue().GetStringValue()
				break
			}
		}
		if !otlpvendor.IsEcho(attrs) && otlpvendor.ClaimsService(svc) {
			if mine == nil {
				mine = &coltracepb.ExportTraceServiceRequest{}
			}
			mine.ResourceSpans = append(mine.ResourceSpans, rs)
			continue
		}
		if rest == nil {
			rest = &coltracepb.ExportTraceServiceRequest{}
		}
		rest.ResourceSpans = append(rest.ResourceSpans, rs)
	}
	return mine, rest
}

// otlpTransientWrite reports whether a store write error is worth a resend of
// the same export: SQLite lock contention or a cancelled / timed-out write.
// Everything else (a constraint, schema drift, a full disk) is a poison record
// for this export and is logged and skipped.
func otlpTransientWrite(err error) bool {
	return db.IsTransientWriteError(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// noteWrite folds one write error into the export's result: a transient one
// becomes the first ErrRetryLater cause, a permanent one is only logged.
func (o *otlpIngest) noteWrite(first *error, err error, msg string, args ...any) {
	if err == nil {
		return
	}
	o.logger.Warn(msg, append(args, "err", err)...)
	if *first == nil && otlpTransientWrite(err) {
		*first = fmt.Errorf("%w: %w", otlpingest.ErrRetryLater, err)
	}
}

// apply writes one mapped export through the store seams, per the
// admission each vendor gets on this node. It returns a non-nil error
// (wrapping otlpingest.ErrRetryLater) only when a write failed transiently.
func (o *otlpIngest) apply(ctx context.Context, res otlpvendor.Result) error {
	var retry error
	for _, svc := range res.Unclaimed {
		o.warnOnce("unclaimed:"+svc, "otlp ingest: no mapping for this exporter's service.name; its records were not captured (see `observer adapters`)", "service_name", svc)
	}
	type admitKey struct {
		tool    string
		proxied bool
	}
	admissions := map[admitKey]otlpvendor.Admission{}
	// admit resolves a vendor's admission. viaRoute is the export's own
	// launcher route marker (a turn's ViaProxyRoute); tool calls and
	// content pass false, which the table resolves identically because the
	// proxy route only ever moves token ownership.
	admit := func(tool string, viaRoute bool) (otlpvendor.Vendor, otlpvendor.Admission) {
		v, _ := otlpvendor.ForTool(tool)
		proxied := viaRoute || (o.proxyRouted != nil && o.proxyRouted(tool))
		k := admitKey{tool, proxied}
		a, ok := admissions[k]
		if !ok {
			a = otlpvendor.AdmitWith(v, otlpvendor.AdmitInput{TranscriptCapture: o.transcriptCapture(tool), ProxyRouted: proxied})
			admissions[k] = a
			if a.Refused != "" {
				o.warnOnce("refused:"+tool, "otlp ingest: export not accepted on a node", "tool", tool, "reason", a.Refused)
			}
			if a.TokensOwner != "" {
				o.warnOnce("tokens-owner:"+tool, "otlp ingest: export token rows not stored", "tool", tool, "reason", a.TokensOwner)
			}
		}
		return v, a
	}

	sessionModel := map[string]string{} // session -> model, for the tool-call rows
	for _, t := range res.Turns {
		v, a := admit(t.Tool, t.ViaProxyRoute)
		if !a.Tokens {
			continue
		}
		if t.Model != "" && t.SessionID != "" {
			sessionModel[t.SessionID] = t.Model
		}
		o.noteWrite(&retry, o.ensureSession(ctx, v, t.SessionID, t.Model, t.Timestamp),
			"otlp ingest: session not created", "tool", v.Tool, "session", t.SessionID)
		_, _, err := o.st.UpsertTurnByRequestID(ctx, apiTurnFromOTLP(t))
		o.noteWrite(&retry, err, "otlp ingest: upsert failed", "tool", t.Tool, "request_id", t.RequestID)
	}

	var events []models.ToolEvent
	for _, tc := range res.Tools {
		v, a := admit(tc.Tool, false)
		if !a.Tools || tc.SessionID == "" {
			continue
		}
		o.noteWrite(&retry, o.ensureSession(ctx, v, tc.SessionID, sessionModel[tc.SessionID], tc.Timestamp),
			"otlp ingest: session not created", "tool", v.Tool, "session", tc.SessionID)
		events = append(events, toolEventFromOTLP(v, tc, sessionModel[tc.SessionID]))
	}
	if len(events) > 0 {
		_, err := o.st.Ingest(ctx, events, nil, store.IngestOptions{})
		o.noteWrite(&retry, err, "otlp ingest: tool calls not stored", "count", len(events))
	}

	// Generation timing for the transcript's own token rows (AP-131
	// follow-up): earlier stamps still waiting for their row go first, then
	// this export's. A stamp never adds a row, so it is not a token write.
	o.retryPendingGenTimings(ctx)
	var stamps []store.TranscriptGenStamp
	for _, gt := range res.GenTimings {
		if _, a := admit(gt.Tool, false); a.Timing {
			stamps = append(stamps, genStampFromOTLP(gt))
		}
	}
	o.stampGenTimings(ctx, stamps)

	if o.captureContent {
		var keep []otlpvendor.Content
		for _, c := range res.Contents {
			if _, a := admit(c.Tool, false); a.Content {
				keep = append(keep, c)
			}
		}
		o.noteWrite(&retry, o.ingestContent(ctx, keep), "otlp ingest: content store failed", "count", len(keep))
	}
	return retry
}

// ensureSession makes sure a session row exists for a capture the vendor's
// row lets create sessions (EnsureCaptureSession only ever inserts).
func (o *otlpIngest) ensureSession(ctx context.Context, v otlpvendor.Vendor, sessionID, model string, ts time.Time) error {
	if sessionID == "" || v.NoSessionRows {
		return nil
	}
	_, err := o.st.EnsureCaptureSession(ctx, sessionID, v.Tool, otlpvendor.PlaceholderProjectRoot(v.Tool), model, ts)
	return err
}

// warnOnce logs a warning the first time its key is seen.
func (o *otlpIngest) warnOnce(key, msg string, args ...any) {
	if _, loaded := o.warned.LoadOrStore(key, true); !loaded {
		o.logger.Warn(msg, args...)
	}
}

// apiTurnFromOTLP converts a mapped turn to the store's API-turn observation.
func apiTurnFromOTLP(t otlpvendor.Turn) models.APITurn {
	return models.APITurn{
		Provider:            t.Provider,
		Model:               t.Model,
		RequestID:           t.RequestID,
		SessionID:           t.SessionID,
		Timestamp:           t.Timestamp,
		InputTokens:         t.InputTokens,
		OutputTokens:        t.OutputTokens,
		CacheReadTokens:     t.CacheReadTokens,
		CacheCreationTokens: t.CacheWriteTokens,
		CostUSD:             t.CostUSD,
		TotalResponseMS:     t.DurationMS,
		TimeToFirstTokenMS:  t.TimeToFirstTokenMS,
		Source:              t.SourceTag,
	}
}

// toolEventFromOTLP converts a mapped tool call to a ToolEvent. The source
// file is the export itself ("otlp:<tool>"), so a redelivered call upserts
// the same action row (UNIQUE(source_file, source_event_id)).
func toolEventFromOTLP(v otlpvendor.Vendor, tc otlpvendor.ToolCall, model string) models.ToolEvent {
	action := v.ActionTypes[tc.Name]
	if action == "" {
		action = models.ActionUnknown
	}
	return models.ToolEvent{
		SourceFile:    "otlp:" + tc.Tool,
		SourceEventID: tc.CallID,
		SessionID:     tc.SessionID,
		ProjectRoot:   otlpvendor.PlaceholderProjectRoot(tc.Tool),
		Timestamp:     tc.Timestamp,
		Tool:          tc.Tool,
		Model:         model,
		ActionType:    action,
		RawToolName:   tc.Name,
		Success:       !tc.SuccessKnown || tc.Success,
		DurationMs:    tc.DurationMS,
	}
}

// ingestContent scrubs captured content bodies for secrets at the boundary
// (otlpvendor stays pure), bounds each to contentMaxBytes, and stores them.
// Best-effort: a content-store failure logs and never fails the turn ingest
// above. The returned error is the store's, for the caller to classify.
//
// Scrubber choice: [scrub.Scrubber.String], not [scrub.Scrubber.ScrubForward].
// ScrubForward exists to protect a body being FORWARDED upstream as a request
// (the proxy path) — its whole purpose is guaranteeing the output stays valid
// JSON so a mangled secret-redaction never truncates a live API request.
// otel_content bodies are never forwarded anywhere; they are stored, once,
// same as raw_tool_input. Content is a single OTel attribute/body string
// (prompt text, tool I/O text): even where it holds JSON tool arguments it is
// stored, not parsed or forwarded, so String is the correct, already-
// idiomatic choice here (same as scrub.RawJSON's non-JSON fallback for
// raw_tool_input).
//
// Cap: bounding happens AFTER scrubbing (a redaction marker, bare or
// typed "[REDACTED:<type>]", replaces the whole secret before any cut, so
// scrub-then-cut can only ever truncate a marker, never re-expose secret
// bytes; a typed marker may be longer than a short match) and BEFORE the
// hash is computed by the caller (InsertOTelContent hashes whatever Content
// it's handed) — see the ContentHash comment in internal/store/otelcontent.go
// for why the hash must cover the FULL scrubbed body, not the capped one.
func (o *otlpIngest) ingestContent(ctx context.Context, recs []otlpvendor.Content) error {
	if len(recs) == 0 {
		return nil
	}
	rows := make([]models.OTelContent, 0, len(recs))
	for _, r := range recs {
		var ts time.Time
		if r.TimeUnixNano != 0 {
			ts = time.Unix(0, int64(r.TimeUnixNano)).UTC()
		}
		scrubbed := o.scrubber.String(r.Content)
		rows = append(rows, models.OTelContent{
			RequestID:   r.RequestID,
			SessionID:   r.SessionID,
			ToolUseID:   r.ToolUseID,
			Kind:        r.Kind,
			Content:     scrub.TruncateN(scrubbed, o.contentMaxBytes),
			ContentHash: store.HashOTelContent(scrubbed),
			Timestamp:   ts,
			Source:      r.SourceTag,
		})
	}
	_, err := o.st.InsertOTelContent(ctx, rows)
	return err
}
