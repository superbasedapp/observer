//go:build !sbo_omit_agentaccess_relay

package mcpregister

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
)

// register_relay.go is the Agent Access relay half of the registrar, split
// out of register.go by lane MP-L1I (T-715): the project.Writer seam the
// relay projector drives. It belongs to agentaccess.relay, so a `-tags
// sbo_omit_agentaccess_relay` build leaves it and relay_writer.go out
// (internal/mcprelay/project with them); the registrar keeps writing and
// removing Observer's own MCP server entry. Relay-wrapped entries a previous
// build wrote are restored with `observer mcp unwrap` in a build that has
// the component, the same rule as every compiled-out component's teardown.
// ---------------------------------------------------------------------------
// Agent Access P4 - the relay's per-format config writer (doc3 §12.1/§12.2;
// Sol P3+P4 findings 2 + 7, parking decision B5).
//
// The stdio writers above register observer's OWN MCP server. The writer
// below is the project.Writer seam the relay projector drives: it STAGES
// (never touching the file) the rewrite of every existing stdio entry to
// the relay's TRUE stdio wrapper plus the upsert of the relay-owned remote
// entries, COMMITS the staged bytes atomically under a CAS on what it
// staged against, and REVERTS only the relay-owned entries in place under
// its own read-compare-write CAS. Every edit is surgical (relay_writer.go,
// T-397): only the relay-owned members change, every other byte of the
// credential-bearing config stays. It journals NOTHING on its own: the
// sequence (journal rows -> rewrite; restore) is owned by
// internal/mcprelay/project's Projector, the ONE journal owner. Dispatch is
// on the client's locate.Format for the FILE shape and on its
// integration.MCPTarget.Remote row for the remote ENTRY spelling (CLAUDE.md
// #3: capability shape, never tool name). No secret ever lands in a client
// config: the relay injects Authorization at call time, the writer refuses
// an Authorization header outright, and the journal rows the projector
// derives from a stage carry env KEY names only.
// ---------------------------------------------------------------------------

// RelayClients lists this registrar's projection targets: every installed
// tool (Installed) that has a locate row, with Verified = a wrap writer
// exists for its format. Client.Format carries the locate.Format string.
// The cross-OS "cline-windows" bridge target is deliberately absent: the
// wrapper would run inside the WSL daemon's OS while the ORIGINAL server is
// a Windows-side command, which the wrapper cannot spawn - an honest zero,
// never a guessed writer.
func (r *Registrar) RelayClients() []project.Client {
	var out []project.Client
	for _, tool := range r.Installed() {
		loc, ok := r.location(tool)
		if !ok || loc.Refusal() != nil {
			continue
		}
		_, writer := wrapWriters[loc.Format]
		out = append(out, project.Client{Tool: tool, ConfigPath: loc.Path, Format: string(loc.Format), Verified: writer})
	}
	return out
}

// resolveClient fills an empty Client.Format from the locate table (a
// restore-time Client carries only tool + path) and resolves the writer.
func (r *Registrar) resolveClient(c project.Client) (project.Client, formatWriter, error) {
	if c.Format == "" {
		loc, ok := r.location(c.Tool)
		if !ok {
			return c, formatWriter{}, fmt.Errorf("mcp.relay-writer: tool %q has no MCP config location", c.Tool)
		}
		c.Format = string(loc.Format)
		if c.ConfigPath == "" {
			if err := loc.Refusal(); err != nil {
				return c, formatWriter{}, fmt.Errorf("mcp.relay-writer: %w", err)
			}
			c.ConfigPath = loc.Path
		}
	}
	w, ok := wrapWriters[locate.Format(c.Format)]
	if !ok {
		return c, formatWriter{}, fmt.Errorf("mcp.relay-writer: no stdio-wrap writer for format %q (%s)", c.Format, c.Tool)
	}
	return c, w, nil
}

// remoteTargetFor resolves tool (or its "-windows" bridge variant) to the
// registry row's grounded remote target. Every refusal names WHY: no row,
// no grounded remote shape, grounded-but-unwired (hermes), or a bridge
// target on a client without CrossOSBridge.
func remoteTargetFor(tool string) (*integration.MCPRemoteTarget, error) {
	base, isWindows := strings.CutSuffix(tool, "-windows")
	c, ok := integration.For(base)
	if !ok {
		return nil, fmt.Errorf("mcp.relay-writer: tool %q not supported", tool)
	}
	if c.MCP == nil || c.MCP.Remote == nil {
		return nil, fmt.Errorf("mcp.relay-writer: %s has no grounded remote MCP target (registry MCPTarget.Remote is nil)", tool)
	}
	if !c.MCP.Remote.Implemented {
		return nil, fmt.Errorf("mcp.relay-writer: %s grounds a remote MCP target but no writer projects it yet (%s)", tool, c.MCP.Remote.Note)
	}
	if isWindows && !c.MCP.CrossOSBridge {
		return nil, fmt.Errorf("mcp.relay-writer: %s has no cross-OS bridge target", tool)
	}
	return c.MCP.Remote, nil
}

// remoteTransportOf maps the projector's transport word onto the registry
// vocabulary ("" = Streamable HTTP).
func remoteTransportOf(t string) integration.MCPRemoteTransport {
	if t == "sse" {
		return integration.MCPRemoteSSE
	}
	return integration.MCPRemoteStreamableHTTP
}

// validateRemoteEntry checks the entry against the client's grounded shape
// and the no-secret rule.
func validateRemoteEntry(tool string, entry project.RemoteEntry, remote *integration.MCPRemoteTarget) error {
	u, err := url.Parse(entry.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("mcp.relay-writer %s: URL %q must be an absolute http(s) URL", tool, entry.URL)
	}
	transport := remoteTransportOf(entry.Transport)
	if !remote.Supports(transport) {
		return fmt.Errorf("mcp.relay-writer %s: transport %q is not grounded for this client (supports %v)", tool, transport, remote.Transports)
	}
	if remote.TransportKey != "" {
		if _, ok := remote.Spelling[transport]; !ok {
			return fmt.Errorf("mcp.relay-writer %s: registry row carries no on-disk spelling for transport %q", tool, transport)
		}
	}
	if len(entry.Headers) > 0 && !remote.Headers {
		return fmt.Errorf("mcp.relay-writer %s: this client's config grounds no headers map", tool)
	}
	for name := range entry.Headers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "":
			return fmt.Errorf("mcp.relay-writer %s: empty header name", tool)
		case "authorization", "proxy-authorization":
			return fmt.Errorf("mcp.relay-writer %s: refusing to write a %s header - the relay injects credentials, config never carries a secret", tool, name)
		}
	}
	return nil
}

// jsonRemoteEntry builds the shared {"mcpServers":{…}} remote entry from the
// row's spelling table: url, the transport under TransportKey (omitted for a
// client that infers it), headers when set, and the client's static flags.
func jsonRemoteEntry(entry project.RemoteEntry, remote *integration.MCPRemoteTarget) map[string]any {
	out := map[string]any{"url": entry.URL}
	if remote.TransportKey != "" {
		out[remote.TransportKey] = remote.Spelling[remoteTransportOf(entry.Transport)]
	}
	if len(entry.Headers) > 0 {
		out["headers"] = copyHeaders(entry.Headers)
	}
	for k, v := range remote.Flags {
		out[k] = v
	}
	return out
}

// codexRemoteEntry builds Codex's [mcp_servers.<name>] remote table: `url`
// designates a Streamable HTTP server (no transport key exists) and static
// headers ride in `http_headers`. bearer_token_env_var / env_http_headers
// are never emitted - no secret, not even by reference, lands here.
func codexRemoteEntry(entry project.RemoteEntry) map[string]any {
	out := map[string]any{"url": entry.URL}
	if len(entry.Headers) > 0 {
		out["http_headers"] = copyHeaders(entry.Headers)
	}
	return out
}

// opencodeRemoteEntry builds OpenCode's typed remote server: the "mcp"
// object's `{"type":"remote","url":…,"enabled":true,"headers":{…}}` shape
// (the sibling of the {"type":"local"} entry registerOpenCodeJSON writes).
func opencodeRemoteEntry(entry project.RemoteEntry, remote *integration.MCPRemoteTarget) map[string]any {
	out := map[string]any{"type": "remote", "url": entry.URL}
	if len(entry.Headers) > 0 {
		out["headers"] = copyHeaders(entry.Headers)
	}
	for k, v := range remote.Flags {
		out[k] = v
	}
	return out
}

func copyHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// jsonEquivalent reports whether two JSON documents decode to the same
// value (key order / whitespace insensitive).
func jsonEquivalent(a, b []byte) bool {
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}
