package agentlaunch

import (
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// MaturityPlanned is the registry maturity of a row that is listed but has
// no driver yet; it is never offered.
const MaturityPlanned = "planned"

// BackendRow is one probed sandbox backend, as the daemon's sandbox probe
// reports it (dashapi.SandboxBackendAvail, mapped at the cmd boundary).
type BackendRow struct {
	ID        string
	Maturity  string
	Available bool
	// Verification is live, doc, fixture or inferred on this host; anything
	// but live is beta (sandboxvocab.Verification.IsBeta).
	Verification string
	Verdict      string
	Reason       string
}

// SourceRow is one probed workspace source.
type SourceRow struct {
	ID        string
	Available bool
	Reason    string
}

// ToolRow is one probed per-tool sandbox row.
type ToolRow struct {
	Available bool
	Reason    string
}

// Probe is the daemon's sandbox availability, plain data.
type Probe struct {
	// Available is the overall verdict for a launch that names no backend.
	Available bool
	Verdict   string
	Reason    string
	Backends  []BackendRow
	Sources   []SourceRow
	Tools     map[string]ToolRow
}

// Choice is the sandbox decision for one launch.
type Choice struct {
	// Sandboxed is false for an unsandboxed launch.
	Sandboxed bool
	// Backend is the explicit backend the terminal service must use; ""
	// lets its selection table pick (auto).
	Backend string
	// Auto is true when the selection picks.
	Auto bool
}

// choiceRow is one ordered row of the backend choice table. A row either
// refuses (err != nil), decides (done), or passes to the next row.
type choiceRow struct {
	id     string
	decide func(n Normalized, p Probe, c *Choice) (done bool, err *Error)
}

// choiceRows are walked top-down (TestChooseRows: one case per row).
var choiceRows = []choiceRow{
	{"C1-unsandboxed", func(n Normalized, _ Probe, _ *Choice) (bool, *Error) {
		return !n.Sandboxed, nil
	}},
	{"C2-explicit-row", func(n Normalized, p Probe, c *Choice) (bool, *Error) {
		if n.Auto {
			return false, nil
		}
		row, ok := findBackend(p.Backends, n.Backend)
		switch {
		case !ok:
			return false, refuse(CodeSandboxUnavailable, "sandbox", "unknown sandbox backend %q on this daemon (see observer sandbox status)", n.Backend)
		case row.Maturity == MaturityPlanned:
			return false, refuse(CodeSandboxUnavailable, "sandbox", "sandbox backend %s is not offered yet", n.Backend)
		case !row.Available:
			return false, refuse(CodeSandboxUnavailable, "sandbox", "sandbox backend %s is unavailable here (%s): %s", n.Backend, row.Verdict, row.Reason)
		}
		// An explicitly named row is used even when it is beta: naming it
		// is the choice P-062 asks for.
		c.Sandboxed, c.Backend = true, row.ID
		return false, nil
	}},
	{"C3-auto-overall", func(n Normalized, p Probe, _ *Choice) (bool, *Error) {
		if !n.Auto {
			return false, nil
		}
		if !p.Available {
			return false, refuse(CodeSandboxUnavailable, "sandbox", "no sandbox is available here (%s): %s", p.Verdict, p.Reason)
		}
		return false, nil
	}},
	{"C4-auto-never-beta", func(n Normalized, p Probe, c *Choice) (bool, *Error) {
		if !n.Auto {
			return false, nil
		}
		var beta string
		for _, row := range p.Backends {
			if !row.Available || row.Maturity == MaturityPlanned {
				continue
			}
			if !vocab.Verification(row.Verification).IsBeta() {
				c.Sandboxed, c.Auto = true, true
				return false, nil
			}
			if beta == "" {
				beta = row.ID
			}
		}
		if beta != "" {
			return false, refuse(CodeSandboxUnavailable, "sandbox", "auto never picks a beta backend (ruling P-062); %s is available but beta here: name it with --sandbox %s", beta, beta)
		}
		return false, refuse(CodeSandboxUnavailable, "sandbox", "no non-beta sandbox backend is available here")
	}},
	{"C5-workspace-source", func(n Normalized, p Probe, _ *Choice) (bool, *Error) {
		src, ok := findSource(p.Sources, n.Workspace)
		switch {
		case !ok:
			return false, refuse(CodeSandboxUnavailable, "workspace", "workspace source %s is not offered by this daemon", n.Workspace)
		case !src.Available:
			return false, refuse(CodeSandboxUnavailable, "workspace", "workspace source %s is not available: %s", n.Workspace, src.Reason)
		}
		return false, nil
	}},
	{"C6-tool-sandboxable", func(n Normalized, p Probe, _ *Choice) (bool, *Error) {
		t, ok := p.Tools[n.Tool]
		switch {
		case !ok:
			return false, refuse(CodeSandboxUnavailable, "tool", "%s cannot be sandboxed: no grounded sandbox row for this tool", n.Tool)
		case !t.Available:
			return false, refuse(CodeSandboxUnavailable, "tool", "%s cannot be sandboxed: %s", n.Tool, t.Reason)
		}
		return true, nil
	}},
}

// Choose decides the sandbox for a normalized request against the daemon's
// probe. A sandboxed request that cannot be honoured is refused with
// CodeSandboxUnavailable; there is no unsandboxed fallback.
func Choose(n Normalized, p Probe) (Choice, error) {
	var c Choice
	for _, row := range choiceRows {
		done, err := row.decide(n, p, &c)
		if err != nil {
			return Choice{}, err
		}
		if done {
			break
		}
	}
	return c, nil
}

func findBackend(rows []BackendRow, id string) (BackendRow, bool) {
	for _, r := range rows {
		if r.ID == id {
			return r, true
		}
	}
	return BackendRow{}, false
}

func findSource(rows []SourceRow, id string) (SourceRow, bool) {
	for _, r := range rows {
		if r.ID == id {
			return r, true
		}
	}
	return SourceRow{}, false
}
