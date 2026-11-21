package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
)

// OwnAgentSessionSink makes the capture session for a developer's own agent
// (P-228, docs/own-agents.md): a request on a default provider lane that
// carries X-Superbased-Agent lands its turn on a session of tool
// models.ToolCustomAgent. The store implements it; plain values only, so no
// proxy type crosses into the store (CLAUDE.md "Module Boundaries" rule 2).
// It must be insert-only and idempotent: a second call for the same session
// id changes nothing.
type OwnAgentSessionSink interface {
	EnsureOwnAgentSession(ctx context.Context, sessionID, agent, projectRoot, model string, startedAt time.Time) error
}

// ownAgentCtxKey carries the request's resolved ownagent.Claim. It is set
// once at the boundary (serve, after lane resolution) and read by
// resolveAPITurnSessionID and requestClass, so nothing downstream reads the
// headers again or branches on a tool name.
type ownAgentCtxKey struct{}

// ownAgentEnsureTimeout bounds the one session-row write per new session.
const ownAgentEnsureTimeout = 2 * time.Second

// ownAgentClaim returns the claim stamped on r, if any.
func ownAgentClaim(r *http.Request) (ownagent.Claim, bool) {
	c, ok := r.Context().Value(ownAgentCtxKey{}).(ownagent.Claim)
	return c, ok
}

// withOwnAgentClaim resolves the own-agent headers on a DEFAULT-lane request
// and, when the agent header is well formed, stamps the claim on the
// request context. A request on an /up/<id> lane (hosted-app, Plane A), a
// node with the capture off (nil sink: "custom-agent" not in
// enabled_adapters) and a request without a usable agent header all return
// r unchanged, so headerless traffic behaves exactly as before. The two
// headers are stripped from every upstream request regardless
// (copyRequestHeaders: X-Session-Id by name, X-Superbased-* by prefix).
func (p *Proxy) withOwnAgentClaim(r *http.Request) *http.Request {
	// Only a POST makes a model turn; a GET (an SDK's model list) must not
	// open an empty session.
	if p.ownAgentSink == nil || p.ownAgents == nil || r.Method != http.MethodPost || obsUpstreamLane(r) != "" {
		return r
	}
	// An existing identity wins (fix rounds 1 and 2; docs/security.md
	// OWNAGENT-1): when any signal the proxy already uses to classify a
	// client names a registered coding tool, that tool and its session keep
	// the turn, on every node. A header must never move a governed tool's
	// spend off its per-tool cap subject or split its proxy turns from its
	// transcript. The ignored claim is only logged.
	if tool, ok := p.existingToolIdentity(r); ok {
		p.logger.Debug("proxy: own-agent header ignored: the request is a registered coding tool's", "tool", tool, "addr", r.RemoteAddr)
		return r
	}
	claim, st := p.ownAgents.Resolve(r.Header.Get(ownagent.AgentHeader), r.Header.Get(ownagent.SessionHeader), p.now())
	switch st {
	case ownagent.StatusOK:
	case ownagent.StatusMalformed:
		p.logger.Debug("proxy: ignored a malformed own-agent header", "header", ownagent.AgentHeader)
		return r
	default:
		return r
	}
	if claim.SessionStatus == ownagent.StatusMalformed {
		p.logger.Debug("proxy: ignored a malformed own-agent session header", "agent", claim.Agent)
	}
	return r.WithContext(context.WithValue(r.Context(), ownAgentCtxKey{}, claim))
}

// existingToolIdentity reports the registered coding tool an agent-header
// request already belongs to by a signal the proxy used before own-agent
// capture existed, walked in order:
//
//  1. the pid bridge, counting only a connection whose own process is the
//     tool's binary, not a child the tool started (bridgeToolIdentity, N2);
//  2. the client identification table toolSignatures (User-Agent,
//     Originator, X-Title: the same table requestClass falls back to),
//     consulted whenever the bridge misses OR errors, so a bridge failure
//     never lets the header win over a recognisable client (N5), and so a
//     node whose bridge is a stub (off Linux) still recognises a coding
//     tool that sends custom headers, such as Claude Code with
//     ANTHROPIC_CUSTOM_HEADERS (N1).
//
// The answer is data from those two sources, never a tool-name branch.
// Only called for a request that carries the agent header, so headerless
// traffic pays no extra lookup; the production resolver caches per remote
// address, so the request's later lookups reuse the walk.
func (p *Proxy) existingToolIdentity(r *http.Request) (string, bool) {
	if r.Header.Get(ownagent.AgentHeader) == "" {
		return "", false
	}
	if tool, ok := p.bridgeToolIdentity(r); ok {
		return tool, true
	}
	return toolFromHeaders(r.Header)
}

// OwnToolResolver is the optional [SessionResolver] extension that names
// a tool only when the process holding the connection is itself that
// tool's binary, never a descendant the tool merely started
// ((*pidbridge.ProcResolver).ResolveOwnTool). Own-agent capture uses it so
// an agent the developer runs from a coding tool's shell, or inside a
// dashboard-launched `observer <tool>` terminal, is an own agent rather
// than being swallowed into that tool's session (fix round 2, N2).
type OwnToolResolver interface {
	ResolveOwnTool(ctx context.Context, remoteAddr string) (tool string, ok bool, err error)
}

// bridgeToolIdentity reports the tool the pid bridge says the connection's
// own process is. With an OwnToolResolver only the socket owner itself
// counts (an ancestor-only hit is a miss); a resolver without it answers
// from its ordinary tool or session lookup. A lookup error is a miss, never
// an identity.
func (p *Proxy) bridgeToolIdentity(r *http.Request) (string, bool) {
	if p.sessions == nil {
		return "", false
	}
	if or, ok := p.sessions.(OwnToolResolver); ok {
		tool, ok, err := or.ResolveOwnTool(r.Context(), r.RemoteAddr)
		if err != nil || !ok || tool == "" {
			return "", false
		}
		return tool, true
	}
	if tr, ok := p.sessions.(ToolResolver); ok {
		tool, ok, err := tr.ResolveTool(r.Context(), r.RemoteAddr)
		if err != nil || !ok || tool == "" {
			return "", false
		}
		return tool, true
	}
	if _, ok, err := p.sessions.Resolve(r.Context(), r.RemoteAddr); err == nil && ok {
		return "", true
	}
	return "", false
}

// ensureOwnAgentSession makes the claim's session row, unless this process
// has already confirmed it, right before the claim's first turn is
// inserted (insertTurnDetached / insertTurnAndCacheDetached, a guard-denied
// turn included). A request that writes no turn (count_tokens, a failed
// read, an upstream with no usage) therefore never opens a session, and the
// row takes the turn's own provider-reported model (the Gemini lane's model
// is only known from the response). When the first turn has no model (an
// error turn), the first later turn that has one fills it in (N4). The project is the resolved working
// directory when the proxy knows one, else the per-tool placeholder the
// other root-less capture paths use. A failed write is retried by the next
// turn.
func (p *Proxy) ensureOwnAgentSession(r *http.Request, turn models.APITurn) {
	if r == nil {
		return
	}
	claim, ok := ownAgentClaim(r)
	if !ok || !p.ownAgents.NeedsRow(claim.SessionID, turn.Model != "") {
		return
	}
	root := p.requestClass(r, turn.Provider).CWD
	if root == "" {
		root = "[" + models.ToolCustomAgent + "]"
	}
	started := turn.Timestamp
	if started.IsZero() {
		started = p.now()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), ownAgentEnsureTimeout)
	defer cancel()
	if err := p.ownAgentSink.EnsureOwnAgentSession(ctx, claim.SessionID, claim.Agent, root, turn.Model, started); err != nil {
		p.logger.Warn("proxy: own-agent session", "agent", claim.Agent, "session_id", claim.SessionID, "err", err)
		return
	}
	// Only a confirmed write marks the session ready, so a failure leaves
	// the next turn to make the row.
	p.ownAgents.MarkRow(claim.SessionID, turn.Model != "")
}
