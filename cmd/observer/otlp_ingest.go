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
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
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
	// The receiver files a session under the root the watcher and the hooks
	// use (hook_ingestroot.go).
	st := store.New(database)
	st.SetProjectRootResolver(daemonIngestRootResolver())
	ing := newOTLPIngest(st, logger, cfg.Ingest.OTel.CapturesContent(), cfg.Ingest.OTel.MaxContentBytes(),
		enabledAdapterSet(cfg.Observer.Watch.EnabledAdapters)).
		withProxyRoutes(newProxyRouteResolver(serving, userHomeOrEmpty()).Routed)
	ing.planeAOff = planeAOffReason(cfg, planeA)
	go ing.runGenTimingRetry(ctx)
	return ing.logs, ing.traces(planeA)
}

// planeAOffReason is why this machine keeps no AI Apps spans, "" when it
// does (planeA wired). A build without app observability, the setting off,
// and a subsystem that failed to start are told apart (review E-29).
func planeAOffReason(cfg config.Config, planeA otlpingest.TraceHandler) string {
	switch {
	case planeA != nil:
		return ""
	case !appObsCompiledIn():
		return "this build does not include AI Apps on this machine; send app spans online (observability.sdk.destination = online) or install the developer edition"
	case !cfg.Observability.Enabled:
		return "AI Apps is off on this machine ([observability] enabled = false); turn it on in Settings to keep app spans here"
	default:
		return "AI Apps could not start on this machine; see the daemon log"
	}
}

// otlpIngest is the native-telemetry ingest glue (Plane B): it maps an AI
// tool's own OpenTelemetry export through the vendor-agnostic table in
// internal/otlpvendor and writes the result through the existing store
// seams. It is the single seam between the schema-blind network receiver
// (internal/ingest/otlp) and the store. A PERMANENT per-row write error is
// logged and skipped so one poison record never stops the rest of the export
// being written; a trace export then answers it as a failed export (not
// retryable), so a Plane A partial success joined with it cannot hide it
// (FR-M17), while a logs export answers success as before. A
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
	// planeAOff is why the unclaimed (AI Apps) spans of a trace export are
	// not kept on this machine (planeAOffReason); "" keeps the old answer
	// for a receiver that never serves AI Apps (the cloud-session loop).
	planeAOff string
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

// traces returns the trace handler: spans from a resource a Plane B row
// claims (a coding tool's service.name, or the developer's own agent named
// by sbo.agent) are mapped here; every unclaimed resource (an application's
// own GenAI spans, a hosted app, Observer's echo) goes to the Plane A
// handler unchanged when one is configured; a resource the own-agent claim
// table drops (a malformed sbo.agent) goes to neither. The two planes never
// share a resource, and the one table that decides is
// otlpvendor.ClaimTraceResource (internal/ownagent's claim rules).
func (o *otlpIngest) traces(planeA otlpingest.TraceHandler) otlpingest.TraceHandler {
	return func(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
		mine, rest, dropped := splitClaimedTraces(req)
		if dropped > 0 {
			o.warnOnce("own-agent:malformed", "otlp ingest: dropped spans whose sbo.agent resource attribute is not a usable agent name", "resources", dropped)
		}
		var err error
		if mine != nil {
			// A transient write is a resend (retry later); a permanent one
			// (a poison record: logged, the rest of the export still
			// written) is this export's error too, so the exporter sees it
			// and a Plane A partial success joined below cannot hide it
			// (review FR-M17; traceResponse lets any non-partial error in
			// a join decide the answer). Not retryable: no resend loop.
			w := o.write(ctx, otlpvendor.ParseSpans(mine))
			err = w.retry
			if err == nil && w.permanent != nil {
				err = fmt.Errorf("otlp ingest: a coding tool's spans were not all stored: %w", w.permanent)
			}
		}
		if rest != nil && planeA != nil {
			err = errors.Join(err, planeA(ctx, rest))
		}
		if rest != nil && planeA == nil && o.planeAOff != "" && err == nil {
			// Review E-29: an app's spans with AI Apps off or not built
			// are answered as an OTLP partial success with the rejected
			// count, never a silent 200; logged once.
			n := countSpans(rest)
			o.warnOnce("planea-off", "otlp ingest: app spans were not kept: "+o.planeAOff, "spans", n)
			return &otlpingest.PartialTraces{RejectedSpans: n, Message: o.planeAOff}
		}
		return err
	}
}

// countSpans is the number of spans in a trace export.
func countSpans(req *coltracepb.ExportTraceServiceRequest) int64 {
	var n int64
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			n += int64(len(ss.GetSpans()))
		}
	}
	return n
}

// splitClaimedTraces partitions a trace export by resource through the
// claim table: Plane B resources (mine), unclaimed ones (rest, Plane A's)
// and the number dropped from both. Either side is nil when empty.
func splitClaimedTraces(req *coltracepb.ExportTraceServiceRequest) (mine, rest *coltracepb.ExportTraceServiceRequest, dropped int) {
	for _, rs := range req.GetResourceSpans() {
		c := otlpvendor.ClaimTraceResource(rs)
		switch {
		case c.Plane.PlaneB():
			if mine == nil {
				mine = &coltracepb.ExportTraceServiceRequest{}
			}
			mine.ResourceSpans = append(mine.ResourceSpans, rs)
		case c.Plane.KeptFromPlaneA():
			dropped++
		default:
			if rest == nil {
				rest = &coltracepb.ExportTraceServiceRequest{}
			}
			rest.ResourceSpans = append(rest.ResourceSpans, rs)
		}
	}
	return mine, rest, dropped
}

// otlpTransientWrite reports whether a store write error is worth a resend of
// the same export: SQLite lock contention or a cancelled / timed-out write.
// Everything else (a constraint, schema drift, a full disk) is a poison record
// for this export and is logged and skipped.
func otlpTransientWrite(err error) bool {
	return db.IsTransientWriteError(err) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// writeOutcome is one export's write result: the first transient failure
// (as an ErrRetryLater cause: the export is resent) and the first permanent
// one (a poison record: logged, the rest of the export still written).
type writeOutcome struct {
	retry, permanent error
}

// noteWrite folds one write error into the export's result: a transient one
// becomes the first ErrRetryLater cause, a permanent one is logged and kept
// as the first permanent failure.
func (o *otlpIngest) noteWrite(w *writeOutcome, err error, msg string, args ...any) {
	if err == nil {
		return
	}
	o.logger.Warn(msg, append(args, "err", err)...)
	switch {
	case otlpTransientWrite(err):
		if w.retry == nil {
			w.retry = fmt.Errorf("%w: %w", otlpingest.ErrRetryLater, err)
		}
	case w.permanent == nil:
		w.permanent = err
	}
}

// apply writes one mapped export through the store seams, per the
// admission each vendor gets on this node. It returns a non-nil error
// (wrapping otlpingest.ErrRetryLater) only when a write failed transiently;
// a permanent failure is logged and skipped (the logs export's rule).
func (o *otlpIngest) apply(ctx context.Context, res otlpvendor.Result) error {
	return o.write(ctx, res).retry
}

// write is apply with both failure kinds reported (a trace export answers a
// permanent one too, FR-M17).
func (o *otlpIngest) write(ctx context.Context, res otlpvendor.Result) writeOutcome {
	var out writeOutcome
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

	// Cloud-execution stamps (cloud-agents lane CA-B4) first, so a marked
	// session's row exists before its turns land. A vendor this node
	// refuses (team grain) stamps nothing.
	for _, ex := range res.Executions {
		v, a := admit(ex.Tool, false)
		if a.Refused != "" {
			continue
		}
		o.noteWrite(&out, o.stampExecution(ctx, v, ex),
			"otlp ingest: execution stamp failed", "tool", ex.Tool, "session", ex.SessionID)
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
		o.noteWrite(&out, o.ensureSession(ctx, v, t.SessionID, t.Agent, t.Model, t.Timestamp),
			"otlp ingest: session not created", "tool", v.Tool, "session", t.SessionID)
		o.noteWrite(&out, o.upsertTurn(ctx, t), "otlp ingest: upsert failed", "tool", t.Tool, "request_id", t.RequestID)
	}

	var events []models.ToolEvent
	for _, tc := range res.Tools {
		v, a := admit(tc.Tool, false)
		if !a.Tools || tc.SessionID == "" {
			continue
		}
		o.noteWrite(&out, o.ensureSession(ctx, v, tc.SessionID, tc.Agent, sessionModel[tc.SessionID], tc.Timestamp),
			"otlp ingest: session not created", "tool", v.Tool, "session", tc.SessionID)
		ev := toolEventFromOTLP(v, tc, sessionModel[tc.SessionID])
		if tc.Agent != "" {
			// An own agent's session may already carry the working
			// directory the proxy resolved; the action lands under that
			// project instead of moving the session to the placeholder
			// (store.Ingest upserts the session with the event's project).
			if root, rerr := o.st.ProjectRootForSession(ctx, tc.SessionID); rerr == nil && root != "" {
				ev.ProjectRoot = root
			}
		}
		events = append(events, ev)
	}
	if len(events) > 0 {
		_, err := o.st.Ingest(ctx, events, nil, store.IngestOptions{})
		o.noteWrite(&out, err, "otlp ingest: tool calls not stored", "count", len(events))
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
		o.noteWrite(&out, o.ingestContent(ctx, keep), "otlp ingest: content store failed", "count", len(keep))
	}
	return out
}

// ensureSession makes sure a session row exists for a capture the vendor's
// row lets create sessions (EnsureCaptureSession only ever inserts). A
// record that names a developer's own agent (agent non-empty, only the
// own-agent row's records) goes through the own-agent seam instead, the one
// the proxy's X-Superbased-Agent path uses, so the session carries the same
// tool, surface "sdk" and host "agent:<name>" whichever path saw it first.
func (o *otlpIngest) ensureSession(ctx context.Context, v otlpvendor.Vendor, sessionID, agent, model string, ts time.Time) error {
	if sessionID == "" || v.NoSessionRows {
		return nil
	}
	if agent != "" {
		return o.st.EnsureOwnAgentSession(ctx, sessionID, agent, otlpvendor.PlaceholderProjectRoot(v.Tool), model, ts)
	}
	_, err := o.st.EnsureCaptureSession(ctx, sessionID, v.Tool, otlpvendor.PlaceholderProjectRoot(v.Tool), model, ts)
	return err
}

// upsertTurn writes one mapped turn. A turn of a developer's own agent
// (t.Agent set, only the own-agent row's) goes through the store's own-agent
// span seam, which never touches another tool's or plane's row and never
// leaves two rows for a call the proxy also wrote (sdk-2 fix round 1, M1 and
// L4); every other vendor's turn keeps the request-id merge.
func (o *otlpIngest) upsertTurn(ctx context.Context, t otlpvendor.Turn) error {
	if t.Agent != "" {
		_, err := o.st.UpsertOwnAgentSpanTurn(ctx, apiTurnFromOTLP(t))
		return err
	}
	_, _, err := o.st.UpsertTurnByRequestID(ctx, apiTurnFromOTLP(t))
	return err
}

// stampExecution writes one export's cloud-execution attribution through
// the one writer Store.SetSessionExecution. A marker that proves the run's
// transcript is not on this node (CreatesSession) creates the session row
// first, under the tool's placeholder root, even on a NoSessionRows vendor;
// otherwise a session the node has not seen yet is a silent no-op. A
// reference that fails the wire grammar is dropped and the location is
// still stamped, so one odd attribute value never loses the location.
func (o *otlpIngest) stampExecution(ctx context.Context, v otlpvendor.Vendor, ex otlpvendor.Execution) error {
	if ex.SessionID == "" || !models.KnownExecutionLocation(ex.Location) {
		return nil
	}
	if ex.CreatesSession {
		if _, err := o.st.EnsureCaptureSession(ctx, ex.SessionID, v.Tool, otlpvendor.PlaceholderProjectRoot(v.Tool), ex.Model, ex.Timestamp); err != nil {
			return err
		}
	}
	ref := ex.VendorRef
	if ref != "" && !orgcontract.ValidVendorSessionRef(ref) {
		ref = ""
	}
	_, err := o.st.SetSessionExecution(ctx, models.SessionExecution{
		SessionID: ex.SessionID, ExecutionLocation: ex.Location, VendorSessionRef: ref,
	})
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
		// The 1-hour part (a subset), so a turn folded against its
		// transcript twin keeps the twin's TTL split (CA-C7).
		CacheCreation1hTokens: t.CacheWrite1hTokens,
		CostUSD:               t.CostUSD,
		TotalResponseMS:       t.DurationMS,
		TimeToFirstTokenMS:    t.TimeToFirstTokenMS,
		Source:                t.SourceTag,
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
