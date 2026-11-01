package diag

import "github.com/marmutapp/superbased-observer/internal/integration"

// Host-side hook TRUST, per mechanism (hook-parity Lane G, `observer doctor
// --hooks`): some hosts register a hook entry but refuse to dispatch it until
// the user approves it (Codex `[hooks.state]` trusted hashes). Table-driven
// by mechanism (capability shape), never by tool: a lane that adds a trusting
// mechanism (e.g. a Codex-shaped one under another home) adds one row.

// HookTrust is one mechanism's trust read on this machine.
type HookTrust struct {
	// Applicable is false when the mechanism has no host-side trust step
	// (every hook that is registered fires).
	Applicable bool
	// Trusted reports, per observer-owned native event the host config
	// carries, whether the host approved it.
	Trusted map[string]bool
	// Registered lists the observer-owned events the trust read found.
	Registered []string
	// Source is the file the trust state was read from.
	Source string
	// Err is a read problem ("" when the read succeeded); the trust state is
	// then unknown.
	Err string
	// Remedy tells the user how to approve an untrusted entry.
	Remedy string
}

// hookTrustReaders maps a mechanism with a host-side trust step to its
// reader.
var hookTrustReaders = map[integration.HookMechanism]func(homeDir string) HookTrust{
	integration.HookCodexConfig: func(homeDir string) HookTrust {
		st := readCodexHookTrust(homeDir)
		return HookTrust{
			Applicable: true, Trusted: st.trusted, Registered: st.registered, Source: st.hooksPath, Err: st.err,
			Remedy: "run `observer init --codex` (it records trust for Observer's own entries) or approve the entry in codex /hooks (codex requires per-hook trust before dispatch)",
		}
	},
}

// HookTrustFor reads the host-side trust state of mechanism m under homeDir
// (Applicable=false when m has no trust step).
func HookTrustFor(m integration.HookMechanism, homeDir string) HookTrust {
	if r, ok := hookTrustReaders[m]; ok {
		return r(homeDir)
	}
	return HookTrust{}
}
