//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxsignin"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestSignInGateAsksRefusesAndHonoursTheOrg pins the seam's effect before
// any workspace (lane BOXSIGNIN): an interactive launch on a projecting
// row is asked with the consent text, a hosted row is never asked and an
// explicit yes there is refused with the hosted reason, and an org forbid
// (applied through the sandbox managed policy) beats a remembered and a
// per-launch consent, naming the organization.
func TestSignInGateAsksRefusesAndHonoursTheOrg(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "darwin" {
		t.Skip("claude-code keeps its sign-in in the macOS Keychain: the keychain refusal is pinned in internal/sandboxsignin")
	}
	yes := true
	r := &sandboxRuntime{}
	ask := termsvc.PrepareRequest{Tool: "claude-code", SignInAsk: true}
	var q *termsvc.SignInConsentError
	if err := signInGate(ask, r.signInDecision(ask, true, false)); !errors.As(err, &q) || !errors.Is(err, termsvc.ErrSignInConsentNeeded) {
		t.Fatalf("no consent question: %v", err)
	}
	if q.Tool != "claude-code" || len(q.Files) != 1 || q.Files[0] != ".claude/.credentials.json" || !strings.Contains(q.Text, "~/.claude/.credentials.json") {
		t.Fatalf("question %+v", q)
	}
	if err := signInGate(ask, r.signInDecision(ask, true, true)); err != nil {
		t.Fatalf("a hosted row asked: %v", err)
	}
	explicit := termsvc.PrepareRequest{Tool: "claude-code", SignInSeed: &yes}
	if err := signInGate(explicit, r.signInDecision(explicit, true, true)); err == nil || !strings.Contains(err.Error(), sandboxsignin.HostedReason) {
		t.Fatalf("a hosted yes was not refused by name: %v", err)
	}
	// A tool with no grounded sign-in file is never asked.
	other := termsvc.PrepareRequest{Tool: "gemini-cli", SignInAsk: true}
	if err := signInGate(other, r.signInDecision(other, true, false)); err != nil {
		t.Fatalf("a tool with no sign-in row asked: %v", err)
	}
	// The org forbid, through the managed policy's compose row.
	forbid := true
	local := config.TerminalSandboxConfig{SignInSeedTools: []string{"claude-code"}}
	eff, refused := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, SignInSeedForbidden: &forbid}, sandboxManagedEnv{})
	if len(refused) != 0 || !eff.SignInSeedForbidden || len(eff.SignInSeedTools) != 0 {
		t.Fatalf("the org forbid did not apply: %+v %v", eff, refused)
	}
	ro := &sandboxRuntime{cfg: eff}
	if d := ro.signInDecision(termsvc.PrepareRequest{Tool: "claude-code"}, true, false); d.Verdict != sandboxsignin.VerdictRefused || d.Code != "org_forbidden" {
		t.Fatalf("remembered consent beat the org: %+v", d)
	}
	if err := signInGate(explicit, ro.signInDecision(explicit, true, false)); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("a launch yes beat the org: %v", err)
	}
	// false (or absent) leaves the node's own choice: it never turns
	// seeding on or off by itself.
	off := false
	if eff, _ := composeSandboxManaged(local, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, SignInSeedForbidden: &off}, sandboxManagedEnv{}); eff.SignInSeedForbidden || len(eff.SignInSeedTools) != 1 {
		t.Fatalf("a false forbid changed the node: %+v", eff)
	}
	if eff, _ := composeSandboxManaged(config.TerminalSandboxConfig{}, orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, SignInSeedForbidden: &off}, sandboxManagedEnv{}); len(eff.SignInSeedTools) != 0 {
		t.Fatalf("the org turned seeding on: %+v", eff)
	}
}

// TestSandboxCLIAskSignIn pins the CLI prompt's answers.
func TestSandboxCLIAskSignIn(t *testing.T) {
	t.Parallel()
	q := &termsvc.SignInConsentError{Tool: "codex", Files: []string{".codex/auth.json"}, Text: sandboxsignin.ConsentText("codex", []string{".codex/auth.json"})}
	for in, want := range map[string][2]bool{"y\n": {true, false}, "always\n": {true, true}, "\n": {false, false}, "n\n": {false, false}, "": {false, false}} {
		var out bytes.Buffer
		yes, remember, err := sandboxCLIAskSignIn(strings.NewReader(in), &out, q)
		if err != nil || yes != want[0] || remember != want[1] {
			t.Errorf("%q: %v %v %v", in, yes, remember, err)
		}
		if !strings.Contains(out.String(), "~/.codex/auth.json") {
			t.Errorf("the prompt does not name the file: %s", out.String())
		}
	}
}

// TestSandboxRememberSignIn: "always" adds the tool to the local config's
// sign_in_seed_tools once, keeping the rest of the file.
func TestSandboxRememberSignIn(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("# mine\n[terminal.sandbox]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := sandboxRememberSignIn(path, "codex"); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "# mine") || strings.Count(string(b), "codex") != 1 || !strings.Contains(string(b), "sign_in_seed_tools") {
		t.Fatalf("config after remember:\n%s", b)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil || len(cfg.Terminal.Sandbox.SignInSeedTools) != 1 || cfg.Terminal.Sandbox.SignInSeedTools[0] != "codex" {
		t.Fatalf("loaded %v %v", cfg.Terminal.Sandbox.SignInSeedTools, err)
	}
}

// TestSandboxSignInDoctorLine: the posture line names the remembered tools
// and the org's forbid, never a file's content.
func TestSandboxSignInDoctorLine(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cfg  config.TerminalSandboxConfig
		want string
	}{
		{config.TerminalSandboxConfig{}, "none remembered"},
		{config.TerminalSandboxConfig{SignInSeedTools: []string{"codex"}}, "copied without asking for codex"},
		{config.TerminalSandboxConfig{SignInSeedForbidden: true}, "organization forbids"},
	} {
		c := sandboxSignInDoctorChecks(tc.cfg)
		if len(c) != 1 || c[0].Name != "sandbox.sign_in_seed" || !strings.Contains(c[0].Message, tc.want) {
			t.Errorf("%+v: %+v", tc.cfg, c)
		}
		// Every line also says what seeding does not cover (P-183).
		if len(c) == 1 && (!strings.Contains(c[0].Message, "clean-copy container runs") || !strings.Contains(c[0].Message, "sign-in included")) {
			t.Errorf("%+v: the line does not say bound rows share the sign-in: %s", tc.cfg, c[0].Message)
		}
	}
}

// TestSandboxSignInSharedEnv: the launch names the tool to the box, an
// inherited value never survives, and the box allow-list carries it.
func TestSandboxSignInSharedEnv(t *testing.T) {
	t.Parallel()
	in := []string{"PATH=/usr/bin", sandboxenv.EnvSignInShared + "=spoofed"}
	got := strings.Join(withSandboxSignInShared(in, "codex"), " ")
	if strings.Contains(got, "spoofed") || !strings.Contains(got, sandboxenv.EnvSignInShared+"=codex") {
		t.Fatalf("env %s", got)
	}
	if got := strings.Join(withSandboxSignInShared(in, ""), " "); strings.Contains(got, sandboxenv.EnvSignInShared) {
		t.Fatalf("a projected run kept an inherited value: %s", got)
	}
	launch := sandboxLaunchEnv([]string{"PATH=/usr/bin"}, termsvc.LaunchRequest{SandboxSignInShared: "claude-code"})
	if !strings.Contains(strings.Join(sandboxBoxEnv("linux", launch), " "), sandboxenv.EnvSignInShared+"=claude-code") {
		t.Fatalf("the box allow-list dropped the shared sign-in: %v", sandboxBoxEnv("linux", launch))
	}
}

// TestSandboxSignInCodexKeyring (audit finding 5): Codex can keep its
// sign-in in the OS keyring, so a consented run with no auth.json says the
// keychain reason, not "no sign-in file".
func TestSandboxSignInCodexKeyring(t *testing.T) {
	t.Parallel()
	yes := true
	d := (&sandboxRuntime{}).signInDecision(termsvc.PrepareRequest{Tool: "codex", SignInSeed: &yes}, true, false)
	if !d.KeychainIfMissing || !strings.Contains(sandboxsignin.PostureLine("codex", d, nil), sandboxsignin.KeychainReason) {
		t.Fatalf("%+v: %s", d, sandboxsignin.PostureLine("codex", d, nil))
	}
}

// TestSandboxSignInForbiddenSeamReadsTheComposedView (audit finding 3): the
// Settings card's forbid comes from the in-force managed policy composed
// onto the file, which the file alone never carries.
func TestSandboxSignInForbiddenSeamReadsTheComposedView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[terminal.sandbox]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seam := sandboxSignInForbiddenSeam(path)
	defer processSandboxManaged.observe(orgclient.ManagedPullOutcome{})
	if seam() {
		t.Fatal("forbidden with no managed policy")
	}
	future := time.Now().Add(time.Hour).Unix()
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 7, ExpiresAt: future, Body: []byte(`{"schema":"sbo-sandbox-managed-v1","sign_in_seed_forbidden":true}`)})
	if !seam() {
		t.Fatal("the composed forbid did not reach the seam")
	}
}
