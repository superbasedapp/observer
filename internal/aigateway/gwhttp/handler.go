package gwhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/marmutapp/superbased-observer/internal/aigateway"
	"github.com/marmutapp/superbased-observer/internal/aigateway/providerext"
)

// Header names the gateway reads. The virtual key arrives as a Bearer token or
// x-api-key (whichever the tool speaks); the rest are gateway-specific.
const (
	HeaderAuthorization = "Authorization"
	HeaderAPIKey        = "X-Api-Key" //nolint:gosec // G101: HTTP header name, not a credential
	HeaderMachine       = "X-SBO-Machine"
	HeaderUpstream      = "X-SBO-Upstream"
	HeaderThin          = "X-SBO-Thin"
	HeaderRequestID     = "X-SBO-Request-Id"
	// HeaderBudgetWarning carries a SOFT budget breach back to the agent:
	// "<level>/<scope_id> <pct>%" per exceeded scope, semicolon-separated
	// (plan §3.2). It is stamped on an ADMITTED response; a HARD breach is a
	// 402 with a structured body instead.
	HeaderBudgetWarning = "X-SBO-Budget-Warning"
)

// MemberResolver resolves a member's roles/teams for model-policy evaluation.
// It is a seam onto org RBAC (owned by another lane); the default NoMember
// returns an empty principal so policy falls back to its DefaultAllow tier.
type MemberResolver interface {
	Resolve(ctx context.Context, orgID, userID string) (aigateway.Principal, error)
}

// NoMember is the default resolver: every member is an empty principal.
type NoMember struct{}

// Resolve returns an empty principal.
func (NoMember) Resolve(context.Context, string, string) (aigateway.Principal, error) {
	return aigateway.Principal{}, nil
}

// Handler runs the §2.4 request pipeline. All fields are injected so the whole
// flow is testable with fakes and the v1.5 standalone split is mechanical.
type Handler struct {
	OrgID     string
	Keys      *AuthCache
	Budgets   aigateway.BudgetStore
	Audit     aigateway.AuditStore
	Upstreams aigateway.UpstreamStore
	Secrets   aigateway.SecretResolver
	Guard     aigateway.GuardScanner
	Members   MemberResolver
	Dialer    Upstreamer

	// ProviderExt is the injection seam for pluggable native-protocol
	// upstreams (Bedrock, Vertex, ...) that fall outside the core's closed
	// ParserForKind vocabulary. Nil (the zero value) is today's behavior,
	// byte-identical: an unknown kind is refused exactly as before this
	// field existed. When set, a kind the registry claims is dispatched via
	// forwardProviderExt instead of h.Dialer.
	//
	// ProviderExtSigner is passed through to the adapter's AttachAuth for
	// signature-based auth (e.g. Bedrock SigV4); adapters that don't need a
	// signer (e.g. Vertex's OAuth bearer) ignore it. ProviderExtClient is
	// the HTTP client used to dial provider-ext upstreams; nil defaults to
	// &http.Client{} per call.
	ProviderExt       *providerext.Registry
	ProviderExtSigner providerext.Signer
	ProviderExtClient *http.Client

	// Admission is the Plane-B judged-admission gate (design §4.6, G1-JUDGED-
	// ADM): consulted after the egress guard, pre-first-byte, before any
	// reservation or dial. Nil ⇒ no admission step (today's behavior).
	Admission aigateway.AdmissionGate

	// MemberCreds resolves the per-developer secret ref for upstreams in
	// CredentialPerDeveloper mode (design §2.3; migration 120). Nil, or a
	// member with no mapping, FAILS CLOSED (502 credential_unavailable) — the
	// gateway never silently falls back to the shared org credential for a
	// per-developer upstream.
	MemberCreds aigateway.MemberCredentialStore

	// Rates and Policy are funcs so the rate card and model policy can be
	// hot-reloaded without rebuilding the handler.
	Rates  func() aigateway.RateCard
	Policy func() aigateway.ModelPolicy

	Limits aigateway.StreamLimits
	Conc   *aigateway.ConcurrencyLimiter
	// StrictRevocationCheckEvery throttles the per-chunk strict-revocation
	// probe (AuthCache.StrictRevocationCheck): at most one watermark read per
	// interval per in-flight stream. Zero ⇒ DefaultStrictRevocationCheckEvery;
	// negative ⇒ probe on every chunk (tests).
	StrictRevocationCheckEvery time.Duration
	ModeGeneration             int64
	HardMaxOutputTokens        int
	Now                        func() time.Time
	Log                        *slog.Logger
}

// now returns the handler clock (time.Now by default).
func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// ServeHTTP is the gateway entrypoint. It runs every blocking decision
// pre-first-byte (§2.7), then streams the upstream response, settles the
// reservation, and writes the metadata-only audit row.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := h.now()
	limits := h.Limits.Normalize()

	// Cap the body before any parse work (§2.7).
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxBodyBytes)
	body, err := readAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the gateway limit")
		return
	}

	// One request id for the whole flow — the gateway-issued idempotency key
	// echoed through the node proxy (§2.4 dedup) and the audit row's PK.
	requestID := h.requestID(r)
	presentedKey := extractKey(r)
	machine := r.Header.Get(HeaderMachine)
	thin := r.Header.Get(HeaderThin) == "1"

	// 1. Authn (fail-closed: a missing/bad key is rejected before anything else).
	key, reject, err := h.Keys.Resolve(r.Context(), h.OrgID, presentedKey, machine, thin)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "authn_unavailable", "key resolution failed")
		return
	}
	if reject != aigateway.RejectNone {
		writeJSONError(w, keyRejectStatus(reject), string(reject), "virtual key rejected: "+string(reject))
		return
	}

	meta := aigateway.ParseRequestMeta(body)
	if meta.Model == "" {
		writeJSONError(w, http.StatusBadRequest, "no_model", "request body must name a model")
		return
	}

	// 2. Model policy.
	principal, err := h.Members.Resolve(r.Context(), h.OrgID, key.UserID)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "member_unavailable", "member resolution failed")
		return
	}
	verdict := h.Policy().Resolve(principal, meta.Model)
	if !verdict.Allowed {
		h.writeAudit(r.Context(), auditFor(h, requestID, key, aigateway.Upstream{}, meta.Model, started, false, verdict.Reason, http.StatusForbidden, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusForbidden, "model_not_allowed", "model not permitted by policy: "+verdict.Reason)
		return
	}

	// 3. Egress guard on the request, pre-first-byte.
	if aigateway.AbortOnScan(h.Guard.ScanRequest(body)) {
		h.writeAudit(r.Context(), auditFor(h, requestID, key, aigateway.Upstream{}, meta.Model, started, false, "egress_guard", http.StatusForbidden, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusForbidden, "egress_guard", "request blocked by egress policy")
		return
	}

	// 3b. Plane-B judged admission (design §4.6), pre-first-byte.
	admissionObserved, admitted := h.admit(w, r, requestID, key, principal, meta.Model, body, started)
	if !admitted {
		return
	}

	// Resolve the target upstream + parser (fixes the wrong-parser-fallthrough).
	upstream, ok := h.resolveUpstream(r, w)
	if !ok {
		return
	}
	parser, ok := aigateway.ParserForKind(upstream.Kind)
	var (
		extAdapter providerext.ProviderAdapter
		useExt     bool
	)
	if !ok {
		// The core's closed vocabulary doesn't know this kind — give the
		// injected external-adapter registry (Bedrock, Vertex, ...) a
		// chance before refusing. A nil ProviderExt (or a registry that
		// doesn't claim this kind) preserves the original refusal exactly.
		extAdapter, useExt = h.ProviderExt.Lookup(string(upstream.Kind))
		if !useExt {
			writeJSONError(w, http.StatusBadGateway, "unsupported_kind", "upstream kind has no gateway parser: "+string(upstream.Kind))
			return
		}
	}

	// 4. Budget: atomic worst-case reservation across every scope, in BOTH
	// denominations (plan R2d).
	effMax := h.Policy().EffectiveMaxOutputTokens(meta.Model, meta.MaxTokens, h.HardMaxOutputTokens)
	rate := h.Rates()
	// G4, NARROWED (plan §3.2): the unpriced-model refusal is no longer
	// decided here, because whether it applies is a property of the in-scope
	// CAPS, not of the model. A model the rate card cannot price would reserve
	// $0 headroom against a USD cap (the original hole) but is bounded
	// perfectly well by a TOKEN cap, which needs no price. Only the budget
	// store knows which units the caps are written in, so the fact travels
	// with the reservation and the store returns Unpriced when the refusal
	// genuinely applies. This is a capability branch on the cap, not on the
	// model.
	_, priced := rate.Rate(meta.Model)
	estInput := aigateway.EstimateInputTokens(len(body))
	worstCase := aigateway.WorstCaseCostUSD(rate, meta.Model, estInput, effMax)
	worstCaseTokens := aigateway.WorstCaseTokens(estInput, effMax)

	// 5. Concurrency (per-key + global), non-blocking.
	if lr := h.Conc.Acquire(key.KeyID); lr != aigateway.LimitNone {
		writeJSONError(w, http.StatusTooManyRequests, string(lr), "concurrency limit reached: "+string(lr))
		return
	}
	defer h.Conc.Release(key.KeyID)

	outcome, err := h.Budgets.Reserve(r.Context(), aigateway.ReservationRequest{
		RequestID:       requestID,
		OrgID:           h.OrgID,
		UserID:          key.UserID,
		Model:           meta.Model,
		Owner:           aigateway.OwnerDeveloper,
		WorstCaseUSD:    worstCase,
		WorstCaseTokens: worstCaseTokens,
		ModelUnpriced:   !priced,
		Scopes:          h.scopes(key, principal),
		Now:             started,
	})
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "budget_unavailable", "budget reservation failed")
		return
	}
	if outcome.Unpriced {
		// An unpriced model under a USD-denominated cap: refuse before any
		// reservation or dial, exactly as before this narrowing. Price the
		// model (add a rate-card entry), or denominate the cap in tokens.
		h.writeAudit(r.Context(), auditFor(h, requestID, key, upstream, meta.Model, started, false, "model_unpriced", http.StatusForbidden, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusForbidden, "model_unpriced", "model has no rate-card entry and cannot be budget-priced against a USD cap; refused")
		return
	}
	if outcome.Replayed {
		// A settled request id replayed: refuse WITHOUT forwarding (F3). Audited
		// as a refused request so the replay is visible, but no upstream call and
		// no budget movement.
		h.writeAudit(r.Context(), auditFor(h, requestID, key, upstream, meta.Model, started, false, "replayed_request", http.StatusConflict, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusConflict, "replayed_request", "request id already settled; replay refused")
		return
	}
	if outcome.InFlight {
		// An unsettled duplicate whose reservation was ALREADY forwarded (G5):
		// refuse WITHOUT re-dialing. Re-admitting would trigger a second real
		// upstream inference the idempotent Settle books only once — a provider
		// double-bill / ledger under-count. Over-strict is deliberate: a client
		// that crashed after the gateway forwarded but before reading the
		// response cannot re-drive this exact request id until settle/reconcile
		// releases the reservation. No double-bill beats convenience.
		h.writeAudit(r.Context(), auditFor(h, requestID, key, upstream, meta.Model, started, false, "in_flight", http.StatusConflict, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusConflict, "in_flight", "request id already forwarded and not yet settled; duplicate refused")
		return
	}
	if !outcome.Admitted {
		h.writeAudit(r.Context(), auditFor(h, requestID, key, upstream, meta.Model, started, false, "budget_exceeded", http.StatusPaymentRequired, aigateway.Usage{}, 0, int64(len(body))))
		writeBudgetDeny(w, aigateway.NewBudgetDenyBody(outcome))
		return
	}

	// SOFT budget breach (plan §3.2): the request is ADMITTED, but the agent
	// is told, and the audit row records it. The header is stamped before any
	// forward so it survives a streamed response (headers are flushed with
	// the first byte).
	softBreach := budgetWarningHeader(outcome.Warnings)
	if softBreach != "" {
		w.Header().Set(HeaderBudgetWarning, softBreach)
	}

	// Resolve the provider credential in-memory (custody) and stamp the
	// pseudonymous member identity into the body. A per_developer upstream
	// dials with the calling member's OWN mapped ref (dial-time key mapping,
	// design §2.3) and fails closed when none is mapped.
	secretRef, refErr := h.dialSecretRef(r.Context(), upstream, key.UserID)
	var cred string
	if refErr == nil {
		cred, refErr = h.Secrets.Resolve(r.Context(), h.OrgID, secretRef)
	}
	if err := refErr; err != nil {
		reason, msg := "credential_unavailable", "the gateway could not resolve the upstream credential"
		if errors.Is(err, errNoMemberCredential) {
			reason, msg = "per_developer_unmapped", "this upstream is in per_developer credential mode and no credential is mapped for your member — ask an administrator to map one"
		}
		_ = h.Budgets.Settle(r.Context(), aigateway.SettleRequest{RequestID: requestID, ActualUSD: 0, Marker: aigateway.MarkerStreamError, Now: h.now()})
		h.writeAudit(r.Context(), auditFor(h, requestID, key, upstream, meta.Model, started, true, reason, http.StatusBadGateway, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusBadGateway, "credential_unavailable", msg)
		return
	}
	pseudonym := aigateway.PseudonymousMemberID(h.OrgID, key.UserID)
	outBody := aigateway.StampPseudonym(upstream.Kind, body, pseudonym)
	// Clamp the outbound output-cap to the reserved effMax so the upstream can
	// never generate more than the worst-case reservation was priced for (F2 /
	// Sol S1). Applied to the same kind the parser speaks; an omitted cap is
	// bounded rather than left to the provider's own large default.
	outBody = aigateway.ClampMaxOutputTokens(upstream.Kind, outBody, effMax)

	// Stamp the reservation forwarded IMMEDIATELY before dialing (G5). This is
	// deliberately over-strict: a crash AFTER the mark but BEFORE the dial makes
	// a genuine retry get 409 in_flight (which reconcile/settle later releases),
	// which is safe — whereas marking AFTER the dial would leave the exact
	// window this closes (a duplicate landing between a successful upstream
	// response and Settle) able to double-forward. Idempotent, so a genuine
	// pre-mark retry that rode the same reservation does not lose the first mark.
	if err := h.Budgets.MarkForwarded(r.Context(), requestID, h.now()); err != nil {
		_ = h.Budgets.Settle(r.Context(), aigateway.SettleRequest{RequestID: requestID, ActualUSD: 0, Marker: aigateway.MarkerStreamError, Now: h.now()})
		h.writeAudit(r.Context(), auditFor(h, requestID, key, upstream, meta.Model, started, true, "forward_mark_failed", http.StatusServiceUnavailable, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusServiceUnavailable, "budget_unavailable", "the gateway could not record the forward")
		return
	}

	// 6. Forward + stream (pass-through, abort-on-detect). A provider-ext
	// kind dispatches through its adapter's own URL/auth/usage mapping
	// instead of the OpenAI/Anthropic wire conventions h.Dialer speaks.
	abortCheck := h.Keys.StrictRevocationCheck(r.Context(), h.OrgID, key, h.strictRevocationEvery())
	result, ferr := h.forward(w, r, forwardTarget{
		upstream: upstream, parser: parser, extAdapter: extAdapter, useExt: useExt,
	}, cred, outBody, meta, limits, abortCheck)
	// Credential is done; drop the local reference promptly.
	cred = "" //nolint:ineffassign // deliberate: drop the credential reference after use

	usage := result.Usage
	actual, _ := rate.EstimateUSD(meta.Model, usage)
	marker := result.AbortMarker
	if ferr != nil && marker == "" {
		marker = aigateway.MarkerStreamError
	}
	// Settlement is idempotent; the refund is implicit (settled rows count
	// actual, not worst-case, in the next reservation's committed sum).
	_ = h.Budgets.Settle(r.Context(), aigateway.SettleRequest{
		RequestID: requestID, ActualUSD: actual, ActualTokens: billableTokens(usage),
		Usage: usage, Marker: marker, Now: h.now(),
	})

	status := result.StatusCode
	if ferr != nil && status == 0 {
		status = http.StatusBadGateway
	}
	ev := auditFor(h, requestID, key, upstream, meta.Model, started, true, softBreachReason(outcome.Warnings), status, usage, actual, int64(len(body)))
	ev.RequestID = requestID
	ev.RateCardVersion = rate.Version
	ev.AbortMarker = marker
	ev.GuardFlagged = result.GuardFlagged || admissionObserved != ""
	ev.DurationMS = h.now().Sub(started).Milliseconds()
	h.writeAudit(r.Context(), ev)
}

// admit runs the Plane-B judged admission gate (design §4.6) pre-first-byte.
// Deterministic layers run first inside the gate; a deny under enforce is a
// 403 the coding agent can act on (audited, then written here — the caller
// just returns); an observe-mode finding rides the audit row only, surfaced as
// the returned criterion. A nil Admission admits everything unobserved.
func (h *Handler) admit(w http.ResponseWriter, r *http.Request, requestID string, key aigateway.VirtualKey, principal aigateway.Principal, model string, body []byte, started time.Time) (observed string, ok bool) {
	if h.Admission == nil {
		return "", true
	}
	verdict := h.Admission.Admit(r.Context(), aigateway.AdmissionRequest{
		Text: aigateway.ExtractPromptText(body), UserID: key.UserID,
		Pseudonym: aigateway.PseudonymousMemberID(h.OrgID, key.UserID), Model: model, Principal: principal,
	})
	if !verdict.Allowed {
		reason := "admission_denied"
		if verdict.Criterion != "" {
			reason += ":" + verdict.Criterion
		}
		h.writeAudit(r.Context(), auditFor(h, requestID, key, aigateway.Upstream{}, model, started, false, reason, http.StatusForbidden, aigateway.Usage{}, 0, int64(len(body))))
		writeJSONError(w, http.StatusForbidden, "admission_denied", "request refused by the org's coding-agent admission policy: "+verdict.Reason)
		return "", false
	}
	if verdict.Observed {
		return verdict.Criterion, true
	}
	return "", true
}

// forwardTarget is the resolved dispatch target for one request: the upstream
// plus EITHER the core parser for its kind OR the external provider adapter
// (useExt) that claimed a kind the core vocabulary doesn't know.
type forwardTarget struct {
	upstream   aigateway.Upstream
	parser     aigateway.Parser
	extAdapter providerext.ProviderAdapter
	useExt     bool
}

// forward performs step 6 (forward + stream, pass-through, abort-on-detect).
// A provider-ext kind dispatches through its adapter's own URL/auth/usage
// mapping instead of the OpenAI/Anthropic wire conventions h.Dialer speaks.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, t forwardTarget, cred string, outBody []byte, meta aigateway.RequestMeta, limits aigateway.StreamLimits, abortCheck func() (bool, string)) (ForwardResult, error) {
	if t.useExt {
		client := h.ProviderExtClient
		if client == nil {
			client = &http.Client{}
		}
		return forwardProviderExt(r.Context(), client, w, ForwardRequest{
			Upstream:         t.upstream,
			Credential:       cred,
			Body:             outBody,
			Model:            meta.Model,
			Stream:           meta.Stream,
			Guard:            h.Guard,
			MaxDuration:      limits.MaxDuration,
			MaxResponseBytes: limits.MaxBodyBytes,
			AbortCheck:       abortCheck,
		}, t.extAdapter, h.ProviderExtSigner)
	}
	return h.Dialer.Forward(r.Context(), w, ForwardRequest{
		Upstream:    t.upstream,
		Parser:      t.parser,
		Credential:  cred,
		Body:        outBody,
		PathSuffix:  h.pathSuffix(r),
		Stream:      meta.Stream,
		Guard:       h.Guard,
		MaxDuration: limits.MaxDuration,
		AbortCheck:  abortCheck,
	})
}

// resolveUpstream picks the target upstream from the X-SBO-Upstream header, or
// the single enabled upstream when the header is absent. Ambiguity (0 or many
// with no header) is a 400 rather than a silent guess.
func (h *Handler) resolveUpstream(r *http.Request, w http.ResponseWriter) (aigateway.Upstream, bool) {
	if id := strings.TrimSpace(r.Header.Get(HeaderUpstream)); id != "" {
		u, err := h.Upstreams.GetUpstream(r.Context(), h.OrgID, id)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "unknown_upstream", "no such upstream: "+id)
			return aigateway.Upstream{}, false
		}
		return u, true
	}
	list, err := h.Upstreams.ListUpstreams(r.Context(), h.OrgID)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "upstream_unavailable", "upstream lookup failed")
		return aigateway.Upstream{}, false
	}
	if len(list) != 1 {
		writeJSONError(w, http.StatusBadRequest, "ambiguous_upstream", "specify X-SBO-Upstream (0 or several upstreams configured)")
		return aigateway.Upstream{}, false
	}
	return list[0], true
}

// scopes builds the hierarchical reservation scopes for a request: key, member,
// each team, and org — on BOTH the daily and monthly window (Reserve enforces
// only scopes that actually have a configured cap).
func (h *Handler) scopes(key aigateway.VirtualKey, pr aigateway.Principal) []aigateway.BudgetScope {
	var out []aigateway.BudgetScope
	add := func(level aigateway.BudgetLevel, id string) {
		if id == "" {
			return
		}
		out = append(
			out,
			aigateway.BudgetScope{Level: level, ID: id, Window: aigateway.WindowDaily},
			aigateway.BudgetScope{Level: level, ID: id, Window: aigateway.WindowMonthly},
		)
	}
	add(aigateway.LevelKey, key.KeyID)
	add(aigateway.LevelMember, key.UserID)
	for _, team := range pr.Teams {
		add(aigateway.LevelTeam, team)
	}
	add(aigateway.LevelOrg, h.OrgID)
	return out
}

// requestID uses the inbound gateway request id when present (an idempotent
// retry), otherwise mints one. The id is echoed through the node proxy so both
// writers' rows carry the same identity (§2.4 dedup).
func (h *Handler) requestID(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get(HeaderRequestID)); id != "" {
		return id
	}
	return "gw-" + uuid.NewString()
}

// pathSuffix returns the inbound request path so the dialer targets the same
// provider endpoint the tool asked for.
func (h *Handler) pathSuffix(r *http.Request) string {
	return r.URL.Path
}

// writeAudit persists a metadata-only audit row, logging (never failing the
// request) on a write error.
func (h *Handler) writeAudit(ctx context.Context, e aigateway.AuditEvent) {
	if err := h.Audit.Write(ctx, e); err != nil && h.Log != nil {
		h.Log.Warn("aigateway: audit write failed", "request_id", e.RequestID, "err", err)
	}
}

// extractKey pulls the virtual key from x-api-key or an Authorization bearer.
func extractKey(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get(HeaderAPIKey)); k != "" {
		return k
	}
	auth := strings.TrimSpace(r.Header.Get(HeaderAuthorization))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[len("bearer "):])
	}
	return ""
}

// auditFor builds a base audit event from the common fields.
func auditFor(h *Handler, requestID string, key aigateway.VirtualKey, u aigateway.Upstream, model string, started time.Time, admitted bool, denyReason string, status int, usage aigateway.Usage, actualUSD float64, reqBytes int64) aigateway.AuditEvent {
	return aigateway.AuditEvent{
		RequestID:      requestID,
		OrgID:          h.OrgID,
		UserID:         key.UserID,
		KeyID:          key.KeyID,
		UpstreamID:     u.UpstreamID,
		Model:          model,
		Kind:           u.Kind,
		Owner:          aigateway.OwnerDeveloper,
		Route:          aigateway.RouteGateway,
		ModeGeneration: h.ModeGeneration,
		Usage:          usage,
		EstimatedUSD:   actualUSD,
		Admitted:       admitted,
		DenyReason:     denyReason,
		StatusCode:     status,
		StartedAt:      started,
		RequestBytes:   reqBytes,
	}
}

// DefaultStrictRevocationCheckEvery bounds the strict-revocation probe cost:
// one watermark read per 500ms per in-flight stream, so a strict revoke
// propagates to open streams within ~0.5s on the instance that serves them.
const DefaultStrictRevocationCheckEvery = 500 * time.Millisecond

func (h *Handler) strictRevocationEvery() time.Duration {
	switch {
	case h.StrictRevocationCheckEvery < 0:
		return 0
	case h.StrictRevocationCheckEvery == 0:
		return DefaultStrictRevocationCheckEvery
	default:
		return h.StrictRevocationCheckEvery
	}
}

// errNoMemberCredential is the fail-closed refusal for a per_developer
// upstream with no mapping for the calling member.
var errNoMemberCredential = errors.New("gwhttp: per_developer upstream has no credential mapped for this member")

// dialSecretRef picks the secret ref to dial an upstream with: the shared org
// ref for single_org upstreams; the member's own mapping for per_developer
// upstreams (never the shared ref — a missing mapping is errNoMemberCredential).
func (h *Handler) dialSecretRef(ctx context.Context, u aigateway.Upstream, userID string) (string, error) {
	if aigateway.NormalizeCredentialMode(u.CredentialMode) != aigateway.CredentialPerDeveloper {
		return u.SecretRef, nil
	}
	if h.MemberCreds == nil {
		return "", errNoMemberCredential
	}
	ref, found, err := h.MemberCreds.MemberSecretRef(ctx, h.OrgID, u.UpstreamID, userID)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errNoMemberCredential
	}
	return ref, nil
}

// budgetWarningHeader renders the SOFT-breach header value: one
// "<level>/<scope_id> <pct>%" clause per exceeded scope, semicolon-separated.
// Empty when nothing was exceeded, so the caller stamps no header at all
// rather than an empty one.
func budgetWarningHeader(ws []aigateway.BudgetWarning) string {
	if len(ws) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ws))
	for _, wn := range ws {
		parts = append(parts, string(wn.Level)+"/"+wn.ScopeID+" "+
			strconv.FormatFloat(wn.Pct*100, 'f', 0, 64)+"% ("+string(wn.Unit)+")")
	}
	return strings.Join(parts, "; ")
}

// softBreachReason is the audit marker for an ADMITTED request that exceeded
// a soft cap. It names the FIRST exceeded scope (the levels are walked
// key→member→team→org, so the first is the narrowest), which is the one an
// operator acts on. Empty for an ordinary admission, so today's audit rows
// are byte-identical.
func softBreachReason(ws []aigateway.BudgetWarning) string {
	if len(ws) == 0 {
		return ""
	}
	return "budget_soft_breach:" + string(ws[0].Level) + "/" + ws[0].ScopeID
}

// billableTokens is the token count a reservation settles at: the same
// input+output sum WorstCaseTokens reserved against, so reserve and settle
// speak one unit. Cache-read/write tokens are excluded for the same reason
// the worst case ignores them — they only ever reduce the real number, and
// counting them here would settle ABOVE what was reserved.
func billableTokens(u aigateway.Usage) int64 {
	n := int64(u.InputTokens) + int64(u.OutputTokens)
	if n < 0 {
		return 0
	}
	return n
}
