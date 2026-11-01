// Package xcodehost is Xcode's host vocabulary for the agent sessions it
// runs (surface-gap FU-193).
//
// Xcode 26.6 runs its agents (Claude Agent, Codex, Gemini) with the working
// directory ~/Library/Autosave Information, not the project open in Xcode
// (MAC-6, 2026-10-30: all three sessions were filed under that folder while
// ~/superbasedtest was open). A session filed by its cwd therefore lands in
// a "project" that is Xcode's autosave folder.
//
// Where the open project is named is not grounded: no captured transcript,
// rollout or hook fixture carries it in a form Observer can rely on (the
// Xcode-injected "Project structure" context of the first user message has
// not been captured; the Codex host trust entry names the autosave folder
// itself). Until a Mac run grounds it, such a session is filed under the
// explicit ProjectUnknown answer rather than the autosave path.
//
// Pure: no I/O at all (pinned by imports_test.go).
package xcodehost

import "strings"

// ProjectUnknown is the project an Xcode agent session is filed under when
// its working directory is Xcode's agent directory and the open project is
// not known.
const ProjectUnknown = "Xcode (project unknown)"

// agentCwdTail is the home-relative directory Xcode runs its agents in.
const agentCwdTail = "/Library/Autosave Information"

// IsAgentCwd reports whether p is <home>/Library/Autosave Information, the
// working directory Xcode gives its agents (either separator, a trailing
// separator ignored, the folder names compared without case as APFS does).
func IsAgentCwd(p string) bool {
	s := strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/")
	if len(s) <= len(agentCwdTail) {
		return false
	}
	head, tail := s[:len(s)-len(agentCwdTail)], s[len(s)-len(agentCwdTail):]
	return strings.EqualFold(tail, agentCwdTail) && strings.Trim(head, "/") != ""
}

// ProjectRoot returns the project a session whose project root resolved to
// root is filed under: ProjectUnknown for Xcode's agent directory, root
// itself for anything else.
func ProjectRoot(root string) string {
	if IsAgentCwd(root) {
		return ProjectUnknown
	}
	return root
}
