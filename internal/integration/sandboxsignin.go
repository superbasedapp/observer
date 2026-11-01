package integration

import (
	"slices"
	"sort"
)

// sandboxsignin.go is the sign-in side of a tool's sandbox row (lane
// BOXSIGNIN, operator ruling P-180 (6), tracker R-186): the files the
// vendor's own docs name as the tool's sign-in. A sandboxed run whose tool
// state is projected (it starts from an empty per-run copy of the state,
// projectionseed.go) may get a COPY of these files, only with the user's
// consent for that tool (internal/sandboxsignin decides; the copy itself is
// the cmd seam's). It is data only: a driver reads the row, never the
// tool's name.

// SandboxSignIn declares where a tool keeps its sign-in on disk.
type SandboxSignIn struct {
	// Files are the HOME-relative sign-in files, each strictly inside one
	// of the row's StateRW entries. Only these are ever copied.
	Files []string
	// KeychainOn lists the GOOS values on which the vendor keeps the
	// sign-in in the system keychain (or a credential manager) instead of
	// a file. There sign-in seeding is refused with a named reason: it
	// covers file sign-ins only.
	KeychainOn []string
	// Artifacts are the internal/agentconfig FileRow ids of Files, in the
	// same order: the cmd seam resolves each through the vendor's own
	// relocation variable (CLAUDE_CONFIG_DIR, CODEX_HOME) with
	// agentconfig.ResolveArtifact before it copies anything.
	Artifacts []string
	// MayUseKeychain says the vendor can keep the sign-in in the system
	// keychain instead (a store setting in a file Observer never reads), so
	// a missing file is reported with the keychain reason.
	MayUseKeychain bool
	// Grounding names the vendor document (and what it says) the fields
	// were read from.
	Grounding string
	// DocURL is that vendor document.
	DocURL string
}

// KeychainOnOS reports whether the vendor keeps the sign-in in the system
// keychain on goos.
func (s SandboxSignIn) KeychainOnOS(goos string) bool { return slices.Contains(s.KeychainOn, goos) }

// SandboxSignInFor returns tool's sign-in row; ok is false when none is
// grounded (sign-in seeding is then refused for the tool).
func SandboxSignInFor(tool string) (SandboxSignIn, bool) {
	c, ok := For(tool)
	if !ok || c.Sandbox.SignIn == nil || len(c.Sandbox.SignIn.Files) == 0 {
		return SandboxSignIn{}, false
	}
	s := *c.Sandbox.SignIn
	s.Files = append([]string(nil), s.Files...)
	s.KeychainOn = append([]string(nil), s.KeychainOn...)
	s.Artifacts = append([]string(nil), s.Artifacts...)
	return s, true
}

// SandboxSignInTools returns every tool with a grounded sign-in row,
// sorted.
func SandboxSignInTools() []string {
	var out []string
	for _, c := range Capabilities() {
		if _, ok := SandboxSignInFor(c.Tool); ok {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}
