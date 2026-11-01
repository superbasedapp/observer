package clientwire

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// Part names one integration a removal touches.
type Part string

const (
	// PartHooks is the tool's hook entries (hook.Registry.Unregister).
	PartHooks Part = "hooks"
	// PartMCP is the observer MCP server entry (mcpregister.Registrar.Unregister).
	PartMCP Part = "mcp"
	// PartRoute is the persisted proxy route (the proxyroute undo).
	PartRoute Part = "route"
)

// routeRemovers is the closed table of tools with a removable proxy route,
// each mapped to its proxyroute undo. It is keyed by tool because the undo is
// per config file and schema: a probe-lane writer that shares a route KIND
// (kimi-code, crush) must never reach the Claude Code or Codex undo. The
// probe-lane writers have no undo shape yet, exactly like proxyroute's own
// Leave table.
var routeRemovers = map[string]func(*proxyroute.Registrar) proxyroute.RegistrationResult{
	"claude-code": (*proxyroute.Registrar).UnregisterClaudeCode,
	"codex":       (*proxyroute.Registrar).UnregisterCodex,
}

// RouteRemovable reports whether tool has a removable persisted proxy route.
func RouteRemovable(tool string) bool {
	_, ok := routeRemovers[tool]
	return ok && RouteSupported(tool)
}

// RouteRemover returns tool's proxyroute undo, for a caller that already
// holds its own registrar (the dashboard's Compression-page undo).
func RouteRemover(tool string) (func(*proxyroute.Registrar) proxyroute.RegistrationResult, bool) {
	if !RouteRemovable(tool) {
		return nil, false
	}
	return routeRemovers[tool], true
}

// Removable reports whether part can be removed for tool at all.
func Removable(tool string, part Part) bool {
	switch part {
	case PartHooks:
		return HookRemovable(tool)
	case PartMCP:
		return MCPSupported(tool)
	case PartRoute:
		return RouteRemovable(tool)
	case PartTelemetry:
		return TelemetrySupported(tool)
	default:
		return false
	}
}

// RemoveOptions parameterize a Remover.
type RemoveOptions struct {
	// BinaryPath is the observer binary whose entries count as Observer's.
	// Required.
	BinaryPath string
	// HomeDir, when non-empty, pins every registry's home (tests, and a
	// sandboxed dashboard). A pinned home switches off cross-OS
	// auto-detection, exactly as the registries define it.
	HomeDir string
	// ProxyPort is the port whose route counts as this install's; a route
	// pointing anywhere else is kept. Zero means 8820.
	ProxyPort int
	// DryRun computes every change and writes nothing.
	DryRun bool
	// Force removes Observer's entries from a file whose install-time
	// checksum no longer matches (the operator checked why).
	Force bool
	// Getenv reads the relocation variables of every file the removal
	// edits (hooks, MCP entries, routes, exporter configs). nil is the one
	// pinned-home rule (crossmount.HomeEnv, R-188 F1): os.Getenv only when
	// HomeDir is not pinned and the process home is not isolated, and no
	// variable otherwise.
	Getenv func(string) string
	// Writer records who removes a route (routeprov); zero is the CLI.
	Writer routeprov.Writer
}

// Removal is one tool's removal outcome, one field per part asked for and
// applicable (nil otherwise). The raw registry results are kept so the CLI
// prints exactly what it always printed; the dashboard projects them.
type Removal struct {
	Tool  string
	Hooks *hook.UnregistrationResult
	MCP   *mcpregister.UnregistrationResult
	Route *proxyroute.RegistrationResult
	// RouteErr is a route registrar that could not be built.
	RouteErr error
	// Telemetry is the exporter-config removal (T-537).
	Telemetry *TelemetryResult
}

// Remover runs `observer uninstall`'s removal, one tool at a time. It is the
// one seam the CLI and the dashboard share.
type Remover struct {
	opts     RemoveOptions
	hooks    *hook.Registry
	mcp      *mcpregister.Registrar
	route    *proxyroute.Registrar
	routeErr error
	built    bool
}

// NewRemover builds the hook and MCP registries a removal drives. The route
// registrar is built on first use (RouteErr reports its failure).
func NewRemover(opts RemoveOptions) (*Remover, error) {
	if opts.BinaryPath == "" {
		return nil, fmt.Errorf("clientwire.NewRemover: BinaryPath is required")
	}
	opts.Getenv = crossmount.HomeEnv(opts.HomeDir, opts.Getenv)
	if opts.ProxyPort <= 0 {
		opts.ProxyPort = 8820
	}
	hookReg, err := hook.NewRegistry(hook.Options{
		Getenv:     opts.Getenv,
		BinaryPath: opts.BinaryPath,
		DryRun:     opts.DryRun,
		Force:      opts.Force,
		HomeDir:    opts.HomeDir,
	})
	if err != nil {
		return nil, fmt.Errorf("clientwire.NewRemover: %w", err)
	}
	mcpReg, err := mcpregister.NewRegistrar(mcpregister.RegisterOptions{
		Getenv:     opts.Getenv,
		BinaryPath: opts.BinaryPath,
		DryRun:     opts.DryRun,
		Force:      opts.Force,
		HomeDir:    opts.HomeDir,
	})
	if err != nil {
		return nil, fmt.Errorf("clientwire.NewRemover: %w", err)
	}
	return &Remover{opts: opts, hooks: hookReg, mcp: mcpReg}, nil
}

// Installed is the union of the tools the hook and MCP registries detect, in
// their own order (hooks first), without duplicates.
func (r *Remover) Installed() []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{r.hooks.Installed(), r.mcp.Installed()} {
		for _, t := range list {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// RouteRegistrarErr builds the route registrar if needed and reports why it
// could not be built (nil when it is ready).
func (r *Remover) RouteRegistrarErr() error {
	if !r.built {
		r.built = true
		r.route, r.routeErr = proxyroute.NewRegistrar(proxyroute.RegisterOptions{
			Writer:    r.opts.Writer,
			ProxyPort: r.opts.ProxyPort,
			DryRun:    r.opts.DryRun,
			HomeDir:   r.opts.HomeDir,
			Getenv:    r.opts.Getenv,
			// A removal never creates a missing vendor directory (T-742).
			Lock: hook.LockSettingsFileIfPresent,
		})
	}
	return r.routeErr
}

// Remove removes the asked-for parts of tool's wiring. A part that does not
// apply to tool (Removable false) is left nil, so asking for every part is
// always safe.
func (r *Remover) Remove(tool string, parts ...Part) Removal {
	out := Removal{Tool: tool}
	for _, p := range parts {
		if !Removable(tool, p) {
			continue
		}
		switch p {
		case PartHooks:
			res := r.hooks.Unregister(tool)
			out.Hooks = &res
		case PartMCP:
			res := r.mcp.Unregister(tool)
			out.MCP = &res
		case PartRoute:
			if err := r.RouteRegistrarErr(); err != nil {
				out.RouteErr = err
				continue
			}
			res := routeRemovers[tool](r.route)
			out.Route = &res
		case PartTelemetry:
			res := removeTelemetry(tool, TelemetryOptions{
				HomeDir: r.opts.HomeDir, Getenv: r.opts.Getenv, DryRun: r.opts.DryRun,
			})
			out.Telemetry = &res
		}
	}
	return out
}

// Failed reports whether any part of the removal failed.
func (m Removal) Failed() bool {
	return m.RouteErr != nil ||
		(m.Hooks != nil && m.Hooks.Error != nil) ||
		(m.MCP != nil && m.MCP.Error != nil) ||
		(m.Route != nil && m.Route.Error != nil) ||
		(m.Telemetry != nil && m.Telemetry.Error != nil)
}
