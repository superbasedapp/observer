package termcore

import "errors"

// ShellTool is the reserved pseudo-tool name a plain-shell fresh launch is
// recorded and reported under (status feed, run history, remote-sensitivity
// classification). It is never a member of the capability registry's
// launchable-tool set, so it can never collide with a real AI-tool name.
// internal/termsvc re-exports it as termsvc.ShellTool.
const ShellTool = "shell"

var (
	// ErrSandboxUnavailable is returned when a caller requests a sandboxed
	// fresh launch but the terminal service was constructed without a
	// sandbox seam (B9 plan sections 7 and 12, amendment A5). A nil seam means
	// the feature is absent; a sandboxed request FAILS CLOSED rather than
	// silently degrading to an unsandboxed launch. Returned BEFORE a run is
	// minted, so no orphan terminal_runs row is created.
	ErrSandboxUnavailable = errors.New("termsvc: sandboxed launch requested but no sandbox seam is configured")
	// ErrWorkspacePrepFailed wraps a sandbox Prepare error (workspace
	// creation, git clone or bwrap-plan failure). Returned before a run is
	// minted, same fail-closed posture as ErrSandboxUnavailable. The dashboard
	// maps this to a 500.
	ErrWorkspacePrepFailed = errors.New("termsvc: sandbox workspace preparation failed")
	// ErrSignInConsentNeeded is returned (as a *SignInConsentError) when a
	// sandboxed launch could copy the tool's sign-in into its box and the
	// caller, which said it can ask (FreshRequest.SignInAsk), has not
	// answered yet (lane BOXSIGNIN). Returned before any workspace is made.
	// The dashboard answers 409 with the consent question; the CLI prompts.
	ErrSignInConsentNeeded = errors.New("termsvc: the sandboxed launch can copy the tool's sign-in and needs your answer first")
)

// SignInConsentError is the consent question of a sandboxed launch (lane
// BOXSIGNIN): the tool, the HOME-relative sign-in files that would be copied
// (paths only, never content) and the consent text naming them. It matches
// ErrSignInConsentNeeded under errors.Is.
type SignInConsentError struct {
	Tool  string
	Files []string
	Text  string
}

// Error is the consent text.
func (e *SignInConsentError) Error() string { return "terminal_sandbox: " + e.Text }

// Is matches ErrSignInConsentNeeded.
func (e *SignInConsentError) Is(target error) bool { return target == ErrSignInConsentNeeded }
