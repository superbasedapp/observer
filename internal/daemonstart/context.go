package daemonstart

import "strings"

// OtherContext is the other OS context this machine's daemon belongs to.
// The zero value means this context.
type OtherContext struct {
	// Where names it for the operator ("WSL (Ubuntu)", "Windows").
	Where string
	// Hint says how to start the daemon there.
	Hint string
}

// Sibling is an observer.db found in another OS context's home (the
// crossmount scan, diag.DetectCrossEnvSiblingDBs), by its labels only.
type Sibling struct {
	// Origin is the crossmount origin label: "wslhost:<distro>/<user>" (a
	// WSL home seen from Windows) or "wsl-mnt:<user>" (a Windows home seen
	// from WSL).
	Origin string
	// OS is the home's logical OS ("linux", "windows", "darwin").
	OS string
}

// ContextFacts is what OtherContextFor reads.
type ContextFacts struct {
	// OnWindows: this process runs on Windows.
	OnWindows bool
	// NativeDBExists: the database this launcher's config names exists.
	NativeDBExists bool
	// Siblings are the observer.db files in other OS contexts' homes.
	Siblings []Sibling
}

type contextRule struct {
	name  string
	match func(f ContextFacts) (Sibling, bool)
}

// contextRules is the ordered table; one test case per row. The only
// supported cross-OS topology is the daemon in WSL with Windows tools
// bridging their hooks into it (the wsl.exe hook bridge
// internal/hook register_crossos.go writes); there is no reverse bridge.
var contextRules = []contextRule{
	// A Windows observer.exe that sees a WSL home with an observer.db: WSL
	// is the bridge's daemon side, so the daemon belongs there even when a
	// stray Windows database exists (a stale native hook once wrote one).
	{"windows sees the wsl daemon", func(f ContextFacts) (Sibling, bool) {
		if !f.OnWindows {
			return Sibling{}, false
		}
		for _, s := range f.Siblings {
			if s.OS == "linux" {
				return s, true
			}
		}
		return Sibling{}, false
	}},
	// This context never ran a daemon (no database here) while another
	// context did: that one is this machine's daemon.
	{"only another context has a database", func(f ContextFacts) (Sibling, bool) {
		if f.NativeDBExists || len(f.Siblings) == 0 {
			return Sibling{}, false
		}
		return f.Siblings[0], true
	}},
}

// OtherContextFor walks contextRules; the zero OtherContext when the daemon
// belongs to this context.
func OtherContextFor(f ContextFacts) OtherContext {
	for _, r := range contextRules {
		if s, ok := r.match(f); ok {
			return describeSibling(s)
		}
	}
	return OtherContext{}
}

// describeSibling names the other context and how to start the daemon in
// it. Pure.
func describeSibling(s Sibling) OtherContext {
	switch {
	case strings.HasPrefix(s.Origin, "wslhost:"):
		distro := strings.TrimPrefix(s.Origin, "wslhost:")
		if i := strings.IndexByte(distro, '/'); i >= 0 {
			distro = distro[:i]
		}
		where := "WSL"
		if distro != "" {
			where = "WSL (" + distro + ")"
		}
		return OtherContext{
			Where: where,
			Hint:  "open a " + where + " terminal and run `observer start` (or `observer service start` if the service is installed there)",
		}
	case strings.HasPrefix(s.Origin, "wsl-mnt:"):
		return OtherContext{
			Where: "Windows",
			Hint:  "run `observer start` in a Windows terminal (or start superbased from the Start menu)",
		}
	default:
		where := s.Origin
		if where == "" {
			where = "another OS context"
		}
		return OtherContext{Where: where, Hint: "run `observer start` there"}
	}
}
