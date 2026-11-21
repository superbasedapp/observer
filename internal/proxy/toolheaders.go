package proxy

import (
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// toolSignature is one row of the header → tool identification table:
// when the named request header carries the given case-insensitive
// prefix, the connection is attributed to the normalized tool
// identity. Evidence is client-controlled (a local process talking to
// its own local proxy), so a row only ever selects behaviour where a
// spoofed match costs the spoofer nothing it could not already choose:
// which compression profile applies, the tool-version stamp, and whether
// an X-Superbased-Agent header may claim the request as an own agent (a
// recognised coding tool keeps its identity, internal/proxy/ownagent.go
// existingToolIdentity). Never an authorization decision.
type toolSignature struct {
	header string // canonical header name, looked up via http.Header.Get
	prefix string // case-insensitive prefix the header value must carry
	tool   string // normalized models.Tool* identity
	// versioned marks a row whose header value is "<prefix><version>
	// [ rest]": the token right after the prefix is the tool's own build
	// version (T-784). Only User-Agent product tokens carry one; the
	// Originator / X-Title rows name the tool without a version.
	versioned bool
}

// toolSignatures is the L1 tool-resolution fallback table for the
// compression profile router's per-tool tier (R2). The pidbridge is fed
// only for tools a hook, an adapter session seed, a dashboard terminal or
// launch seed or an Arena binding registered (the SessionStart hook's
// ancestor walk being the main feeder), so a hookless client launched
// outside the dashboard used to resolve tool="" and silently skip
// [profiles.by_tool] / tool: experiment classes (deviation D20,
// docs/plans/usability-review-2026-06-10.md §10.2). Rows below are the
// signals each client was VERIFIED to send (installed-bundle string
// extraction, 2026-06-12; codex corroborated by the live 0.133 wire
// capture in docs/observer-platform-issues-v4.md V4-4):
//
//   - claude-code ≥2.1: UA "claude-cli/<ver> …" (plus x-app: cli). The
//     bridge normally wins for claude-code; this row is the safety net
//     for installs without registered hooks. Known mimic: pi spoofs
//     the claude-cli UA for subscription auth — inert, since the
//     anthropic provider tier resolves the claude-code profile anyway.
//   - codex (codex-rs): UA "codex_cli_rs/<ver> (…)" and an
//     "Originator: codex_cli_rs" header on both auth paths.
//   - kilo CLI (@kilocode/cli): gateway-provider requests carry
//     "X-Title: Kilo Code" (no custom UA — Bun's default); the
//     anthropic-direct path sets UA "Kilo-Code/<ver>". Kilo is an
//     opencode fork that still ships opencode-UA code paths, so kilo
//     rows MUST sort before opencode rows (first hit wins).
//   - opencode: provider headers "X-Title: opencode" and UA
//     "opencode/<ver>" on its own fetches.
//
// Deliberately absent: cline-cli sends only stock SDK UAs
// (anthropic-sdk-typescript/axios — nothing distinctive), so it keeps
// degrading to the per-provider tier until a cline hook feeder ships;
// copilot-cli, cursor, and hermes talk to their own backends and never
// reach the proxy's upstreams.
var toolSignatures = []toolSignature{
	{header: "User-Agent", prefix: "claude-cli/", tool: models.ToolClaudeCode, versioned: true},
	{header: "User-Agent", prefix: "codex_cli_rs/", tool: models.ToolCodex, versioned: true},
	{header: "Originator", prefix: "codex", tool: models.ToolCodex},
	{header: "User-Agent", prefix: "Kilo-Code/", tool: models.ToolKiloCodeCLI, versioned: true},
	{header: "X-Title", prefix: "Kilo Code", tool: models.ToolKiloCodeCLI},
	{header: "User-Agent", prefix: "opencode/", tool: models.ToolOpenCode, versioned: true},
	{header: "X-Title", prefix: "opencode", tool: models.ToolOpenCode},
}

// toolVersionFromHeaders resolves the owning tool exactly as
// toolFromHeaders does (first hit wins), then reads that SAME tool's
// build version off a versioned row of the table: the product token
// after the prefix, up to the first space / "(" / ";". A version is only
// returned for the tool the request was attributed to, so a Kilo request
// that also carries an inherited opencode UA never yields an opencode
// version. The token must pass orgcontract.ValidToolVersion (the column's
// one grammar); anything else is ("", "", false). The store seam
// re-validates on write, so this check only keeps junk off the sink.
func toolVersionFromHeaders(h http.Header) (tool, version string, ok bool) {
	tool, ok = toolFromHeaders(h)
	if !ok {
		return "", "", false
	}
	for _, sig := range toolSignatures {
		if !sig.versioned || sig.tool != tool {
			continue
		}
		v := h.Get(sig.header)
		if len(v) <= len(sig.prefix) || !strings.EqualFold(v[:len(sig.prefix)], sig.prefix) {
			continue
		}
		rest := v[len(sig.prefix):]
		if i := strings.IndexAny(rest, " (;"); i >= 0 {
			rest = rest[:i]
		}
		if orgcontract.ValidToolVersion(rest) {
			return tool, rest, true
		}
	}
	return "", "", false
}

// toolFromHeaders resolves a request's owning AI tool from the
// signature table. requestClass consults it ONLY after the pidbridge
// resolver missed (hook-fed bridge identity always wins there), and a
// miss ("", false) leaves the class degrading to the per-provider
// assignment tier, exactly like a bridge miss. existingToolIdentity also
// consults it, after an own-process bridge miss OR a bridge error, to
// decide whether an own-agent header may claim the request.
func toolFromHeaders(h http.Header) (string, bool) {
	for _, sig := range toolSignatures {
		v := h.Get(sig.header)
		if len(v) < len(sig.prefix) {
			continue
		}
		if strings.EqualFold(v[:len(sig.prefix)], sig.prefix) {
			return sig.tool, true
		}
	}
	return "", false
}
