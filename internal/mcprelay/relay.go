package mcprelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// Target is where one call goes: a node-local stdio server the wrapper
// spawned (Local) or a remote virtual server on the org front.
type Target struct {
	// VServer is the virtual-server slug (`/mcp/<slug>` on the front; the
	// vserver id the local PDP table knows).
	VServer string
	// ServerID is the approved registry entry id of a node-local server
	// (the `--server <id>` the wrapper was launched with); "" for remote.
	ServerID string
	// Local marks a node-local stdio server (the local PDP decides; nothing
	// is forwarded to the org front).
	Local bool
}

// Options configure a Relay.
type Options struct {
	// GatewayURL is the org MCP gateway base (https://<gateway_base_host>);
	// a remote target's endpoint is <GatewayURL>/mcp/<slug> and its token
	// resource (exact aud) is the same URI.
	GatewayURL string
	// FrontURL is where the front is DIALLED when it differs from
	// GatewayURL (an internal hostname, a test listener); "" = GatewayURL.
	// The token resource (aud) is always GatewayURL-based; the DPoP proof's
	// htu is the dialled URL.
	FrontURL string
	// Tokens is the STS exchange client (required for remote targets).
	Tokens *TokenClient
	// HTTP performs forwards to the front; built through internal/mcpegress
	// by the composition root (required for remote targets).
	HTTP *http.Client
	// Records is Lane N-M's node record store (required).
	Records record.Store
	// Capture scrubs L2 payloads for storage (nil -> NewCapturer()).
	Capture Capturer
	// CaptureCap is the per-field capture cap (zero -> DefaultCaptureCap).
	CaptureCap int
	// SidecarPath is the loss sidecar (<db dir>/mcp-relay-loss.json). Empty
	// disables the sidecar, which makes every async append failure BLOCK.
	SidecarPath string
	// AuditMode is [mcp_relay].audit_mode: async (default) | strict.
	AuditMode string
	// Local is the node PDP for node-local servers (required for Local
	// targets; a Local call with no decider is refused, never passed).
	Local localpdp.Decider
	// LocalPrincipal builds the token-less principal a local call is decided
	// as (the composition root adapts localpdp.Table.NodePrincipal). ok=false
	// means the vserver is unknown to the table.
	LocalPrincipal func(vserver string, transport localpdp.Transport) (localpdp.Principal, bool)
	// CredentialAssurance is the node's credential assurance recorded on
	// decision rows ("node_enrolled" when empty).
	CredentialAssurance string
	// CaptureLevel is the record capture level: L2 (teams/enterprise) or L0
	// (individual). Empty -> L0 (never a silent raise).
	CaptureLevel string
	// MaxResponse caps a buffered front response (zero -> 32 MiB).
	MaxResponse int64
	// Now is the clock (nil -> time.Now).
	Now func() time.Time
	// Log receives diagnostics - never token material.
	Log *slog.Logger
	// Projects resolves a session's declared working directory to the
	// project hash the relay attests in its actor assertion (P11(e);
	// projectid.go). nil -> NewProjectResolver(nil) (internal/git).
	Projects *ProjectResolver
}

// Relay is the node mediation core shared by every serving mode.
type Relay struct {
	o   Options
	rec *recorder
}

// New validates o, loads any pending loss sidecar, folds it into a gap
// record when the store is writable (§12.4 step 4), and returns the relay.
func New(o Options) (*Relay, error) {
	if o.Records == nil {
		return nil, errors.New("mcprelay.New: Records store is required")
	}
	switch o.AuditMode {
	case "", AuditAsync:
		o.AuditMode = AuditAsync
	case AuditStrict:
	default:
		return nil, fmt.Errorf("mcprelay.New: unknown audit_mode %q", o.AuditMode)
	}
	if o.GatewayURL != "" {
		if _, err := dpop.CanonicalHTU(o.GatewayURL); err != nil {
			return nil, fmt.Errorf("mcprelay.New: gateway url: %w", err)
		}
		o.GatewayURL = strings.TrimRight(o.GatewayURL, "/")
	}
	if o.FrontURL != "" {
		if _, err := dpop.CanonicalHTU(o.FrontURL); err != nil {
			return nil, fmt.Errorf("mcprelay.New: front url: %w", err)
		}
		o.FrontURL = strings.TrimRight(o.FrontURL, "/")
	}
	switch record.CaptureLevel(o.CaptureLevel) {
	case "":
		o.CaptureLevel = string(record.CaptureL0)
	case record.CaptureL0, record.CaptureL1, record.CaptureL2:
	default:
		return nil, fmt.Errorf("mcprelay.New: unknown capture level %q", o.CaptureLevel)
	}
	if o.CredentialAssurance == "" {
		o.CredentialAssurance = "node_enrolled"
	}
	if o.MaxResponse <= 0 {
		o.MaxResponse = 32 << 20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Capture == nil {
		o.Capture = NewCapturer()
	}
	if o.CaptureCap <= 0 {
		o.CaptureCap = DefaultCaptureCap
	}
	if o.Projects == nil {
		o.Projects = NewProjectResolver(nil)
	}
	rec, err := newRecorder(context.Background(), o.Records, o.SidecarPath, o.AuditMode, o.Now)
	if err != nil {
		return nil, fmt.Errorf("mcprelay.New: %w", err)
	}
	r := &Relay{o: o, rec: rec}
	if err := rec.handoff(context.Background()); err != nil {
		r.log().Warn("mcprelay: pending loss not yet handed to the store (kept in the sidecar)", "err", err)
	}
	return r, nil
}

func (r *Relay) log() *slog.Logger {
	if r.o.Log != nil {
		return r.o.Log
	}
	return slog.Default()
}

// PendingLoss reports the unfolded local-append loss (for `observer mcp
// status`).
func (r *Relay) PendingLoss() LossSidecar { return r.rec.pendingLoss() }

// Resource is the exact token audience of a remote target.
func (r *Relay) Resource(t Target) string { return r.o.GatewayURL + "/mcp/" + t.VServer }

// endpoint is the URL the front is dialled at for a remote target.
func (r *Relay) endpoint(t Target) string {
	if r.o.FrontURL != "" {
		return r.o.FrontURL + "/mcp/" + t.VServer
	}
	return r.Resource(t)
}

// Call is one inbound JSON-RPC message with what the serving mode knows
// about its sender.
type Call struct {
	Target Target
	// Raw is the message exactly as the client sent it (forwarded verbatim).
	Raw []byte
	// Transport is what the relay observed; Attestation the claim the mode
	// derived (the wrapper's verified-parent result, "" = the transport's
	// own proof). The effective value is the weaker of the two.
	Transport   localpdp.Transport
	Attestation string
	// Agent / Product identify the product client the mode attested
	// ("agent:claude-code" / "claude-code"); empty = the node-wide principal.
	Agent, Product string
	// Corr carries the coding-session anchors for sbo_corr (R11.8).
	Corr Correlation
	// ProjectHash is the RELAY-ATTESTED project hash of the call's coding
	// session (P11(e)): resolved by the relay's ProjectResolver from the
	// session's declared working directory - never a caller-supplied hash.
	// "" = no project context (project-scoped grants fail closed).
	ProjectHash string
	// ProtocolVersion is the client's Mcp-Protocol-Version when it spoke
	// HTTP; "" lets the message's own _meta / params decide.
	ProtocolVersion string
	// SessionID is a legacy Mcp-Session-Id to carry to the front.
	SessionID string
}

// Verdict is the pre-forward outcome of one call.
type Verdict struct {
	Msg    *Message
	CallID string
	// Refuse is the JSON-RPC error frame to answer with when the call must
	// not proceed (nil = forward). Refused notifications have no frame.
	Refuse []byte
	// Forward is true when the call proceeds to the upstream.
	Forward bool
	// Attestation is the effective client attestation.
	Attestation string
	// Corr is the call's effective correlation (the stream anchors plus a
	// per-call tool-use id from params._meta, corr.go): what the decision
	// record stores and ForwardHTTP signs into sbo_corr.
	Corr Correlation
	// Visible is the local catalogue filter for a listing (nil = none).
	Visible []string

	seq    int64
	start  time.Time
	row    methodRow
	target string
	pv     string
	local  localpdp.Decision
}

// Decide runs everything that must happen BEFORE a forward: parse,
// classify, the local PDP (local targets), and the decision record
// (strict/async ordering). A refused call carries its error frame; a
// blocked record makes the call refuse with CodeUnavailable.
func (r *Relay) Decide(ctx context.Context, c Call) Verdict {
	now := r.o.Now()
	v := Verdict{start: now}
	msg, err := ParseMessage(c.Raw)
	if err != nil {
		code := CodeParse
		if errors.Is(err, ErrBatch) {
			code = CodeInvalidRequest
		}
		v.Refuse = ErrorFrame(nil, code, err.Error())
		return v
	}
	v.Msg = msg
	v.Attestation = localpdp.EffectiveAttestation(c.Transport, c.Attestation)
	if msg.IsResponse() {
		// A client's reply to a server request: relayed, nothing to decide.
		v.Forward = true
		return v
	}
	v.row, v.target, v.pv = classify(msg)
	if c.ProtocolVersion != "" {
		v.pv = c.ProtocolVersion
	}
	v.Corr = c.Corr.forCall(msg)
	id, err := randomID()
	if err != nil {
		v.Refuse = r.refuse(msg, CodeUnavailable, "relay: cannot mint a call id")
		return v
	}
	v.CallID = id

	decision, reason := "allow", "relay: forwarded to the org front"
	var strict bool
	if c.Target.Local {
		d, ok := r.decideLocal(ctx, c, msg, &v)
		if !ok {
			return v
		}
		v.local = d
		strict = d.StrictAudit
		reason = d.Reason
		switch {
		case d.Forwardable():
			decision = "allow"
		case d.Ask():
			decision = "ask"
		default:
			decision = "deny"
		}
		v.Visible = d.Visible
	}
	if r.o.Tokens == nil && !c.Target.Local {
		v.Refuse = r.refuse(msg, CodeUnavailable, "relay: no token client for a remote virtual server")
		return v
	}
	rec := record.Record{
		Kind: record.KindDecision, TS: now.Unix(), Family: record.DefaultFamily,
		VServer: c.Target.VServer, Server: c.Target.ServerID, Tool: v.target, CallID: v.CallID, Method: msg.Method,
		EventKind: record.EventKind(v.row.EventKind), Decision: record.Decision(decision), ReasonCode: reason,
		ClientAttestation: record.ClientAttestation(v.Attestation), CredentialAssurance: r.o.CredentialAssurance,
		CaptureLevel:    record.CaptureLevel(r.o.CaptureLevel),
		CodingSessionID: v.Corr.CodingSessionID, TurnRef: v.Corr.TurnRef, ActionRef: v.Corr.ActionRef,
		CorrConfidence: record.CorrConfidence(corrConfidence(v.Corr)),
	}
	if decision == "deny" {
		rec.EventKind = record.EventDeny
	}
	if r.o.CaptureLevel != string(record.CaptureL2) {
		// Plain names ride only at L2 (R10.6); the store keys the HMAC dims.
		rec.Server, rec.Tool = "", ""
	}
	if r.o.CaptureLevel == string(record.CaptureL2) && len(msg.Params) > 0 && string(msg.Params) != "null" {
		full, st := r.o.Capture.CaptureJSON(msg.Params, r.o.CaptureCap)
		rec.ArgsFull, rec.ArgsScrubStatus = string(full), st
	}
	seq, err := r.rec.decision(ctx, rec, strict)
	if err != nil {
		r.log().Warn("mcprelay: call blocked", "method", msg.Method, "call_id", v.CallID, "err", err)
		v.Refuse = r.refuse(msg, CodeUnavailable, "relay: the decision record could not be made durable; call blocked")
		return v
	}
	v.seq = seq
	if decision != "allow" {
		// The record is durable; now answer the client from the PDP's error.
		if v.local.Error != nil {
			v.Refuse = r.refuse(msg, v.local.Error.Code, v.local.Error.Message)
		} else {
			v.Refuse = r.refuse(msg, CodeForbidden, "forbidden: "+reason)
		}
		r.rec.completion(ctx, r.completionRecord(v, seq, "denied", nil, ""))
		return v
	}
	v.Forward = true
	return v
}

// decideLocal runs the node PDP for a local target. ok=false means v now
// carries the refusal.
func (r *Relay) decideLocal(ctx context.Context, c Call, msg *Message, v *Verdict) (localpdp.Decision, bool) {
	if r.o.Local == nil || r.o.LocalPrincipal == nil {
		v.Refuse = r.refuse(msg, CodeUnavailable, "relay: no local policy loaded; call blocked")
		return localpdp.Decision{}, false
	}
	p, ok := r.o.LocalPrincipal(c.Target.VServer, c.Transport)
	if !ok {
		v.Refuse = r.refuse(msg, CodeForbidden, "relay: virtual server not in the node policy")
		return localpdp.Decision{}, false
	}
	p.ClientAttestation = v.Attestation
	// The relay-attested project of the stream (P11 fold PF2): the wrapper's
	// own spawn directory, resolved by the relay - never a caller value.
	p.ProjectHash = c.ProjectHash
	if c.Agent != "" {
		p.ClientID = c.Agent
	}
	if c.Product != "" {
		p.Product = c.Product
	}
	if msg.IsNotification() {
		// Notifications carry no effect; they are relayed and recorded.
		return localpdp.Decision{Verdict: localpdp.VerdictPass, Effect: "allow", Reason: "notification", DecisionClass: localpdp.ClassCatalogue}, true
	}
	d := r.o.Local.CheckRequest(ctx, localpdp.Request{
		VServerID: c.Target.VServer, Method: msg.Method, Tool: v.target, Params: msg.Params, Server: c.Target.ServerID,
		Principal: p, CallID: v.CallID, JSONRPCID: msg.IDKey(),
	})
	if d.Stripped || d.Verdict == localpdp.VerdictError {
		code, m := localpdp.CodeUnavailable, "relay: cannot decide"
		if d.Error != nil {
			code, m = d.Error.Code, d.Error.Message
		}
		v.Refuse = r.refuse(msg, code, m)
		return d, false
	}
	return d, true
}

// refuse renders an error frame for a request; a notification gets none.
func (r *Relay) refuse(msg *Message, code int, text string) []byte {
	if msg.IsNotification() {
		return []byte{}
	}
	return ErrorFrame(msg.ID, code, text)
}

// corrConfidence is exact when the mode supplied a coding-session anchor.
func corrConfidence(c Correlation) string {
	if c.CodingSessionID != "" || c.TurnRef != "" || c.ActionRef != "" {
		return "exact"
	}
	return "none"
}

// Complete appends the completion record for a forwarded call.
func (r *Relay) Complete(ctx context.Context, v Verdict, status string, body []byte, errBody string) {
	if v.CallID == "" || v.seq == 0 {
		return
	}
	r.rec.completion(ctx, r.completionRecord(v, v.seq, status, body, errBody))
}

// completionRecord shapes one completion row (R14.2: capture_level +
// call_id + decision_seq + result_status required; payloads at L2 only).
func (r *Relay) completionRecord(v Verdict, seq int64, status string, body []byte, errBody string) record.Record {
	now := r.o.Now()
	size := int64(len(body))
	if errBody == "" && len(body) > 0 {
		// A JSON-RPC error reply is the ERROR payload, not a result.
		if m, err := ParseMessage(body); err == nil && m.Error != nil {
			eb, _ := json.Marshal(m.Error)
			errBody, body = string(eb), nil
		}
	}
	rec := record.Record{
		Kind: record.KindCompletion, TS: now.Unix(), Family: record.DefaultFamily, DecisionSeq: record.Int(seq),
		CallID: v.CallID, ResultStatus: status, CaptureLevel: record.CaptureLevel(r.o.CaptureLevel),
		ResultSizeBytes: record.Int(size), LatencyMS: record.Int(now.Sub(v.start).Milliseconds()),
	}
	if r.o.CaptureLevel == string(record.CaptureL2) {
		if len(body) > 0 {
			full, st := r.o.Capture.CaptureJSON(body, r.o.CaptureCap)
			rec.ResultFull, rec.ResultScrubStatus = string(full), st
		}
		if errBody != "" {
			full, st := r.o.Capture.CaptureJSON([]byte(errBody), r.o.CaptureCap)
			rec.ErrorFull, rec.ErrorScrubStatus = string(full), st
		}
	}
	return rec
}

// HTTPReply is the front's answer to one forwarded message.
type HTTPReply struct {
	Status      int
	ContentType string
	Body        []byte
	SessionID   string
	// RetryAfter is the front's Retry-After on a transient refusal (503 /
	// 502), relayed to a loopback client (Lane CHAOS, §10 relay backoff UX).
	RetryAfter string
}

// ErrNotRemote is returned when ForwardHTTP is asked to forward a local call.
var ErrNotRemote = errors.New("mcprelay: target is node-local, not a remote virtual server")

// ForwardHTTP sends one decided call to the org front with a DPoP-bound
// access token and a per-request proof carrying sbo_corr, rotating the
// token and retrying ONCE on a 401 invalid_token. Every failure to obtain
// a token or reach the front is returned as an error (the caller answers
// the client with CodeUnavailable).
func (r *Relay) ForwardHTTP(ctx context.Context, c Call, v Verdict) (*HTTPReply, error) {
	if c.Target.Local {
		return nil, ErrNotRemote
	}
	if r.o.Tokens == nil || r.o.HTTP == nil || r.o.GatewayURL == "" {
		return nil, errors.New("mcprelay.ForwardHTTP: remote forwarding is not configured (gateway url, token client, http client)")
	}
	resource, endpoint := r.Resource(c.Target), r.endpoint(c.Target)
	corr := &dpop.Correlation{CallID: v.CallID, CodingSessionID: v.Corr.CodingSessionID, TurnRef: v.Corr.TurnRef, ActionRef: v.Corr.ActionRef}
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := r.o.Tokens.TokenFor(ctx, resource, v.Attestation, c.ProjectHash)
		if err != nil {
			return nil, fmt.Errorf("mcprelay.ForwardHTTP: %w", err)
		}
		proof, err := r.o.Tokens.Proof(tok, http.MethodPost, endpoint, corr)
		if err != nil {
			return nil, fmt.Errorf("mcprelay.ForwardHTTP: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(c.Raw))
		if err != nil {
			return nil, fmt.Errorf("mcprelay.ForwardHTTP: %w", err)
		}
		req.Header.Set("Authorization", dpop.SchemeDPoP+" "+tok.Value)
		req.Header.Set("DPoP", proof)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if v.pv != "" {
			req.Header.Set("Mcp-Protocol-Version", v.pv)
		}
		if c.SessionID != "" {
			req.Header.Set("Mcp-Session-Id", c.SessionID)
		}
		resp, err := r.o.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("mcprelay.ForwardHTTP: front unreachable: %w", err)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, r.o.MaxResponse+1))
		_ = resp.Body.Close()
		if rerr != nil {
			return nil, fmt.Errorf("mcprelay.ForwardHTTP: read front response: %w", rerr)
		}
		if int64(len(body)) > r.o.MaxResponse {
			return nil, errors.New("mcprelay.ForwardHTTP: front response exceeds the size cap")
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && invalidToken(resp.Header.Get("WWW-Authenticate")) {
			// Rotate-and-retry once: the token was refused (expired,
			// generation floor moved, key rotated). A second 401 is final.
			r.o.Tokens.InvalidateFor(resource, v.Attestation, c.ProjectHash)
			r.log().Info("mcprelay: access token refused by the front; re-exchanging once", "vserver", c.Target.VServer, "call_id", v.CallID)
			continue
		}
		return &HTTPReply{
			Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: body, SessionID: resp.Header.Get("Mcp-Session-Id"),
			RetryAfter: resp.Header.Get("Retry-After"),
		}, nil
	}
	return nil, errors.New("mcprelay.ForwardHTTP: unreachable")
}

// invalidToken reports an RFC 6750 invalid_token challenge.
func invalidToken(www string) bool {
	return strings.Contains(strings.ToLower(www), `error="invalid_token"`)
}

// Frames renders a front reply as the JSON-RPC frames a stdio client
// expects: a JSON body is one frame; an SSE body yields one frame per
// message event; a 202 (accepted notification) yields none. An HTTP-level
// refusal whose body is a JSON-RPC error with a null id is re-addressed to
// the request's id so the client can correlate it; an unparseable refusal
// becomes a CodeUnavailable error for the request.
func (rp *HTTPReply) Frames(reqID json.RawMessage) [][]byte {
	if rp.Status == http.StatusAccepted || len(bytes.TrimSpace(rp.Body)) == 0 {
		if rp.Status >= 400 && len(reqID) > 0 {
			return [][]byte{ErrorFrame(reqID, CodeUnavailable, fmt.Sprintf("relay: front answered %d", rp.Status))}
		}
		return nil
	}
	var frames [][]byte
	if strings.HasPrefix(strings.ToLower(rp.ContentType), "text/event-stream") {
		events, _ := readSSE(bytes.NewReader(rp.Body), int64(len(rp.Body)))
		for _, ev := range events {
			if _, err := ParseMessage(ev.Data); err == nil {
				frames = append(frames, ev.Data)
			}
		}
		return frames
	}
	body := bytes.TrimSpace(rp.Body)
	if rp.Status >= 400 {
		m, err := ParseMessage(body)
		if err != nil || m.Error == nil {
			return [][]byte{ErrorFrame(reqID, CodeUnavailable, fmt.Sprintf("relay: front answered %d", rp.Status))}
		}
		if !m.HasID() && len(reqID) > 0 {
			return [][]byte{ErrorFrame(reqID, m.Error.Code, m.Error.Message)}
		}
	}
	return [][]byte{body}
}

// Outcome classifies a reply for the completion record.
func (rp *HTTPReply) Outcome() string {
	switch {
	case rp.Status == http.StatusUnauthorized, rp.Status == http.StatusForbidden:
		return "denied"
	case rp.Status >= 500, rp.Status == http.StatusNotFound:
		return "unavailable"
	case rp.Status >= 400:
		return "error"
	}
	if m, err := ParseMessage(rp.Body); err == nil && m.Error != nil {
		return "error"
	}
	return "ok"
}

// projectHash is the relay's attestation of a session's declared working
// directory (P11(e)): "" when dir is empty or does not resolve.
func (r *Relay) projectHash(dir string) string { return r.o.Projects.Hash(dir) }
