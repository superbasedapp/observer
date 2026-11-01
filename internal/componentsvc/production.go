package componentsvc

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/clientwire"
)

// TeardownOptions configures the production Teardowner.
type TeardownOptions struct {
	// Remove configures the tool-wiring remover (BinaryPath required; its
	// DryRun is set per call).
	Remove clientwire.RemoveOptions
	// BrowserHost removes the browser native-messaging host (manifests,
	// Windows registry keys, host files) and reports it as one outcome. It
	// is injected by the caller (cmd/observer composes internal/browserhost)
	// so this package never imports the capture.browser component's own
	// package (the component package fence). Nil reports an error step.
	BrowserHost func(dryRun bool) StepOutcome
}

// NewTeardown returns the production Teardowner: internal/clientwire's
// Remover for tool wiring (the seam `observer uninstall` and the dashboard
// already use) and the injected browser-host remover.
func NewTeardown(opts TeardownOptions) Teardowner { return &clientwireTeardown{opts: opts} }

type clientwireTeardown struct{ opts TeardownOptions }

var partByName = map[string]clientwire.Part{
	PartHooks: clientwire.PartHooks, PartMCP: clientwire.PartMCP,
	PartRoute: clientwire.PartRoute, PartTelemetry: clientwire.PartTelemetry,
}

func (t *clientwireTeardown) RemoveToolWiring(tool string, parts []string, dryRun bool) []StepOutcome {
	ro := t.opts.Remove
	ro.DryRun = dryRun
	rm, err := clientwire.NewRemover(ro)
	if err != nil {
		return []StepOutcome{{Target: nonEmpty(tool, "all tools"), Error: err.Error()}}
	}
	var cps []clientwire.Part
	for _, p := range parts {
		if cp, ok := partByName[p]; ok {
			cps = append(cps, cp)
		}
	}
	installed := rm.Installed()
	var targets []string
	if tool == "" {
		targets = installed
	} else {
		targets = []string{tool}
		// The tool's other homes follow it: the cross-OS "-windows"
		// bridge, an Xcode agent home (FU-145) and a WSL twin (FU-197),
		// each only where Installed detected it.
		for _, x := range installed {
			if x != tool && clientwire.HookTargetBase(x) == tool {
				targets = append(targets, x)
			}
		}
	}
	var out []StepOutcome
	for _, target := range targets {
		out = append(out, summarizeRemoval(rm.Remove(target, cps...)))
	}
	return out
}

func summarizeRemoval(m clientwire.Removal) StepOutcome {
	o := StepOutcome{Target: m.Tool}
	if h := m.Hooks; h != nil {
		if h.Error != nil {
			o.Error = joinErr(o.Error, "hooks: "+h.Error.Error())
		}
		if len(h.HooksRemoved) > 0 {
			o.Changed = true
			o.Detail = append(o.Detail, fmt.Sprintf("hooks: %s in %s", strings.Join(h.HooksRemoved, ","), h.ConfigPath))
		}
		if len(h.HooksKept) > 0 {
			o.NeedsAttention = append(o.NeedsAttention, fmt.Sprintf("hooks you wrote kept in %s: %s", h.ConfigPath, strings.Join(h.HooksKept, ",")))
		}
		if len(h.FilesKeptForeign) > 0 {
			o.NeedsAttention = append(o.NeedsAttention, "files kept (not written by Observer): "+strings.Join(h.FilesKeptForeign, ", "))
		}
		if len(h.TrustRemoved) > 0 {
			o.Detail = append(o.Detail, "trust records: "+strings.Join(h.TrustRemoved, ","))
		}
		if h.TrustNote != "" {
			o.NeedsAttention = append(o.NeedsAttention, h.TrustNote)
		}
	}
	if mc := m.MCP; mc != nil {
		if mc.Error != nil {
			o.Error = joinErr(o.Error, "mcp: "+mc.Error.Error())
		}
		if mc.Removed {
			o.Changed = true
			o.Detail = append(o.Detail, "mcp: entry in "+mc.ConfigPath)
		}
	}
	if m.RouteErr != nil {
		o.Error = joinErr(o.Error, "route: "+m.RouteErr.Error())
	}
	if r := m.Route; r != nil {
		if r.Error != nil {
			o.Error = joinErr(o.Error, "route: "+r.Error.Error())
		}
		if r.Added {
			o.Changed = true
			o.Detail = append(o.Detail, "route: "+r.ConfigPath)
		}
	}
	if te := m.Telemetry; te != nil {
		if te.Error != nil {
			o.Error = joinErr(o.Error, "telemetry: "+te.Error.Error())
		}
		if te.Changed {
			o.Changed = true
			o.Detail = append(o.Detail, "telemetry exporter: "+te.ConfigPath)
		}
		if te.Conflict != "" {
			o.NeedsAttention = append(o.NeedsAttention, "telemetry: "+te.Conflict)
		}
	}
	return o
}

func (t *clientwireTeardown) RemoveBrowserHost(dryRun bool) StepOutcome {
	if t.opts.BrowserHost == nil {
		return StepOutcome{Target: "browser native-messaging host", Error: "no browser host remover configured; nothing was removed"}
	}
	return t.opts.BrowserHost(dryRun)
}

func joinErr(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
