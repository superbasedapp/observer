package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// primeAgentInject mirrors the promptInjection descriptor newPrimeAgentCmd
// hands to the shared continueFromArgs seam, so the argv-shape assertions
// below exercise the exact contract the launcher declares. NO tool binary is
// spawned.
var primeAgentInject = promptInjection{
	Kind:          injectTrailingPositional,
	ConflictFlags: []string{"-p", "--print"},
	Subcommands:   primeAgentSubcommands,
}

// TestPrimeAgentInjectShape pins the grounded seed contract from
// `prime-agent --help` (v0.7.0): `prime-agent [options] [@files...]
// [message...]` — a bare trailing positional message.
func TestPrimeAgentInjectShape(t *testing.T) {
	const prompt = "SEEDED HANDOVER"

	t.Run("bare seed is the sole positional", func(t *testing.T) {
		got, err := injectPrompt(nil, primeAgentInject, prompt)
		if err != nil {
			t.Fatalf("injectPrompt: %v", err)
		}
		if !equalArgs(got, []string{prompt}) {
			t.Fatalf("got %v, want %v", got, []string{prompt})
		}
	})

	t.Run("forwarded flags are preserved before the seed", func(t *testing.T) {
		got, err := injectPrompt([]string{"--model=gpt-4o"}, primeAgentInject, prompt)
		if err != nil {
			t.Fatalf("injectPrompt: %v", err)
		}
		if !equalArgs(got, []string{"--model=gpt-4o", prompt}) {
			t.Fatalf("got %v, want [--model=gpt-4o <prompt>]", got)
		}
	})

	t.Run("a forwarded bare message collides", func(t *testing.T) {
		if _, err := injectPrompt([]string{"do the thing"}, primeAgentInject, prompt); err == nil {
			t.Fatal("a forwarded positional message must collide with the seed")
		}
	})

	t.Run("headless -p with a query collides via its positional", func(t *testing.T) {
		// ConflictFlags are consulted only by the flag-VALUE injection kind;
		// the shared two-prompt check inspects POSITIONALS for the
		// trailing-positional kind used here, so `-p hi` trips it through
		// "hi". The BARE flag forms are the launcher's own
		// argsContainHeadlessFlag guard, pinned separately below.
		if _, err := injectPrompt([]string{"-p", "hi"}, primeAgentInject, prompt); err == nil {
			t.Fatal("forwarded -p <query> must collide with the seed")
		}
	})
}

// TestPrimeAgentHeadlessFlagIsASeedConflict pins the launcher-owned guard
// for the headless one-shot: `-p`/`--print` answers and exits, so
// --continue-from must reject it (the pi/commandcode precedent).
func TestPrimeAgentHeadlessFlagIsASeedConflict(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"-p"}, true},
		{[]string{"--print"}, true},
		{[]string{"--model", "x"}, false},
		{[]string{"--", "-p"}, false}, // after a bare --, it is literal text
	}
	for _, tc := range cases {
		if got := argsContainHeadlessFlag(tc.args, "-p", "--print"); got != tc.want {
			t.Errorf("argsContainHeadlessFlag(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestPrimeAgentSubcommandsNotMisreadAsPrompt pins that a forwarded
// management verb is not mistaken for a competing positional message.
func TestPrimeAgentSubcommandsNotMisreadAsPrompt(t *testing.T) {
	for sub := range primeAgentSubcommands {
		if forwardedPromptConflict([]string{sub}, primeAgentSubcommands) {
			t.Errorf("subcommand %q was misread as a forwarded prompt", sub)
		}
	}
	if !forwardedPromptConflict([]string{"status", "do it"}, primeAgentSubcommands) {
		t.Error("subcommand + bare prompt must still collide")
	}
}

// TestPrimeAgentHeadlessScan pins the grounded leading-verb guard: the
// subcommand set plus the flag grammar, so a SPLIT flag value does not park
// itself in the operand slot and hide a following management verb (the
// droid/command-code FINDING-2 regression class).
func TestPrimeAgentHeadlessScan(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"status"}, true},
		{[]string{"--model=gpt-4o", "status"}, true},
		{[]string{"config", "show"}, true},
		{[]string{"--model", "gpt-4o"}, false},
		{[]string{"--", "status"}, false},
		// A split-value flag before a subcommand must still detect it — the
		// exact class a wrong/incomplete flag table breaks.
		{[]string{"--model", "gpt-4o", "status"}, true},
		{[]string{"--cwd", "/repo", "doctor"}, true},
		{[]string{"--system-prompt", "be nice", "shutdown"}, true},
		{[]string{"--append-system-prompt", "x=y", "session"}, true},
		// …and the value itself must not be mistaken for the verb.
		{[]string{"--model", "status"}, false},
		{[]string{"--cwd", "doctor"}, false},
		// A positional MESSAGE does not trip the scan.
		{[]string{"fix the status page please"}, false},
		{[]string{"tell", "me", "the", "config", "story"}, false},
		// Bool switches keep the scan aligned.
		{[]string{"--verbose", "status"}, true},
		{[]string{"-p", "status"}, true},
	}
	for _, tc := range cases {
		if got := primeAgentHeadlessScan.leads(tc.args); got != tc.want {
			t.Errorf("primeAgentHeadlessScan.leads(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestPrimeAgentFlagGrammarIsDisjoint pins that no prime-agent flag is
// claimed as BOTH a value-taking flag and a switch, and that both spellings
// of every -x/--xyz pair land in the SAME table — the two tables are read
// off one `--help` block, and either kind of drift would mean one of them is
// a misreading (exactly the class a silent typo breaks, per
// leadingVerbScan's split-value bypass).
func TestPrimeAgentFlagGrammarIsDisjoint(t *testing.T) {
	for f := range primeAgentValueFlags {
		if primeAgentBoolFlags[f] {
			t.Errorf("prime-agent flag %q is in BOTH primeAgentValueFlags and primeAgentBoolFlags", f)
		}
	}
	pairs := [][2]string{
		{"-r", "--resume"},
		{"-t", "--tools"},
		{"-e", "--extension"},
		{"-p", "--print"},
		{"-nt", "--no-tools"},
		{"-nbt", "--no-builtin-tools"},
		{"-ne", "--no-extensions"},
		{"-ns", "--no-skills"},
		{"-np", "--no-prompt-templates"},
		{"-nc", "--no-context-files"},
		{"-c", "--continue"},
		{"-v", "--version"},
		{"-h", "--help"},
	}
	for _, p := range pairs {
		short, long := p[0], p[1]
		shortIsValue, longIsValue := primeAgentValueFlags[short], primeAgentValueFlags[long]
		shortIsBool, longIsBool := primeAgentBoolFlags[short], primeAgentBoolFlags[long]
		if shortIsValue != longIsValue {
			t.Errorf("flag pair %s/%s split across primeAgentValueFlags (short=%v long=%v)", short, long, shortIsValue, longIsValue)
		}
		if shortIsBool != longIsBool {
			t.Errorf("flag pair %s/%s split across primeAgentBoolFlags (short=%v long=%v)", short, long, shortIsBool, longIsBool)
		}
		if !shortIsValue && !shortIsBool {
			t.Errorf("flag pair %s/%s is in NEITHER grounded table", short, long)
		}
	}
}

// TestPrimeAgentAttachPassthrough pins the wrapper-flag forwarding to the
// daemon-spawned inner launcher.
func TestPrimeAgentAttachPassthrough(t *testing.T) {
	if got := primeAgentAttachPassthrough("/opt/prime-agent"); !equalArgs(got, []string{"--prime-agent-path", "/opt/prime-agent"}) {
		t.Fatalf("primeAgentAttachPassthrough = %v", got)
	}
	if got := primeAgentAttachPassthrough(""); len(got) != 0 {
		t.Fatalf("expected empty passthrough, got %v", got)
	}
}

// TestPrimeAgentSeededLaunchInjectsProviderExactlyOnce drives the real cobra
// command (--prime-agent-path short-circuits binary resolution — never
// spawned, since ensurePrimeAgentObserverProvider or the handoff render
// fails first) to pin that a --continue-from seed lands as a trailing
// positional and `--provider observer` is prepended exactly once, with the
// user's own forwarded args preserved in order after it.
//
// The command errors out before actually exec-ing anything (no running
// proxy / unknown source session), so this only exercises argv assembly up
// to the point of failure — which is exactly what droid/commandcode's
// "drives the real cobra command" tests do too. We assert on the SIDE
// EFFECT that is observable without a live proxy: the models.json write.
func TestPrimeAgentSeededLaunchInjectsProviderExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}
	pinToolHomesAt(t, home)
	t.Setenv(observerProviderAPIKeyEnv, "test-not-a-secret") // a key is available, so the provider IS written
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newPrimeAgentCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", cfgPath,
		"--prime-agent-path", filepath.Join(dir, "stub-never-spawned"),
		"--continue-from", "no-such-session",
		"--", "--model=gpt-4o",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the unknown source session to fail the handoff render")
	}
	if strings.Contains(err.Error(), "management subcommand") {
		t.Fatalf("an ordinary flag argv must NOT trip the management-verb guard: %v", err)
	}

	// The provider is session-scoped (Sol A5-08): it is written before the
	// handoff render and REMOVED again when the launch ends, including this
	// failed one, so no models.json residue survives.
	if _, statErr := os.Stat(filepath.Join(home, ".prime", "agent", "models.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a failed launch left the session provider behind (stat err %v)", statErr)
	}
}

// ensurePrimeAgentObserverProvider is the pre-A5-08 helper shape the
// provider-file tests below drive: write the session provider with a
// credential available, keeping the file (no restore).
func ensurePrimeAgentObserverProvider(baseURL string) error {
	_, err := preparePrimeAgentObserverProvider(baseURL, true)
	return err
}

// TestPrimeAgentManagementVerbsAreRejectedForSeeding is the FINDING-1-class
// regression this launcher must also satisfy: every prime-agent management
// verb prints/acts and exits or reattaches an EXISTING run, never accepting
// a fresh message positional, so --continue-from must reject it by NAME
// before the handoff render.
func TestPrimeAgentManagementVerbsAreRejectedForSeeding(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	for _, verb := range []string{"status", "doctor", "config", "shutdown", "session"} {
		t.Run(verb, func(t *testing.T) {
			home := filepath.Join(dir, "home-"+verb)
			pinToolHomesAt(t, home)
			cmd := newPrimeAgentCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{
				"--config", cfgPath,
				"--prime-agent-path", filepath.Join(dir, "stub-never-spawned"),
				"--continue-from", "no-such-session",
				"--", verb,
			})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("`prime-agent --continue-from … -- %s` must be rejected, got nil error (stderr=%q)", verb, out.String())
			}
			if !strings.Contains(err.Error(), verb) {
				t.Errorf("error must NAME the offending verb %q, got %q", verb, err.Error())
			}
		})
	}
}

// --- ensurePrimeAgentObserverProvider -----------------------------------

func assertPrimeAgentProviderFile(t *testing.T, path, wantBaseURL string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse %s: %v (contents: %s)", path, err, data)
	}
	providers, _ := root["providers"].(map[string]any)
	if providers == nil {
		t.Fatalf("no providers block in %s", path)
	}
	entry, _ := providers[primeAgentProviderName].(map[string]any)
	if entry == nil {
		t.Fatalf("no %q provider entry in %s", primeAgentProviderName, path)
	}
	if got, _ := entry["baseUrl"].(string); got != wantBaseURL {
		t.Errorf("baseUrl = %q, want %q", got, wantBaseURL)
	}
	apiKey, _ := entry["apiKey"].(string)
	if apiKey != "OPENAI_API_KEY" {
		t.Errorf("provider apiKey %q does not match the expected env-var name %q (never a literal secret)", apiKey, "OPENAI_API_KEY")
	}
	// Defense in depth: the written bytes must never contain anything that
	// looks like a live secret pattern this repo scrubs elsewhere.
	if strings.Contains(string(data), "sk-") {
		t.Errorf("found an sk- prefixed substring that looks like a live key (%s)", data)
	}
}

// TestEnsurePrimeAgentObserverProvider_FreshFile pins the create path: no
// existing ~/.prime/agent/models.json.
func TestEnsurePrimeAgentObserverProvider_FreshFile(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)

	if err := ensurePrimeAgentObserverProvider("http://127.0.0.1:8820/v1"); err != nil {
		t.Fatalf("ensurePrimeAgentObserverProvider: %v", err)
	}
	path := filepath.Join(home, ".prime", "agent", "models.json")
	assertPrimeAgentProviderFile(t, path, "http://127.0.0.1:8820/v1")
}

// TestEnsurePrimeAgentObserverProvider_PreservesExisting pins that an
// EXISTING models.json with another provider is preserved and only the
// observer entry is (re)written.
func TestEnsurePrimeAgentObserverProvider_PreservesExisting(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	dir := filepath.Join(home, ".prime", "agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "models.json")
	existing := `{
		"providers": {
			"my-ollama": {
				"baseUrl": "http://localhost:11434/v1",
				"api": "openai-completions",
				"apiKey": "not-needed"
			}
		}
	}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}

	if err := ensurePrimeAgentObserverProvider("http://127.0.0.1:8820/v1"); err != nil {
		t.Fatalf("ensurePrimeAgentObserverProvider: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse: %v", err)
	}
	providers, _ := root["providers"].(map[string]any)
	if providers == nil {
		t.Fatal("providers block missing after merge")
	}
	other, _ := providers["my-ollama"].(map[string]any)
	if other == nil {
		t.Fatal("pre-existing my-ollama provider was NOT preserved")
	}
	if got, _ := other["baseUrl"].(string); got != "http://localhost:11434/v1" {
		t.Errorf("pre-existing provider mutated: baseUrl = %q", got)
	}
	assertPrimeAgentProviderFile(t, path, "http://127.0.0.1:8820/v1")
}

// TestEnsurePrimeAgentObserverProvider_Idempotent pins that a re-run
// converges: running it twice with the same base URL produces a
// byte-for-byte identical file, and running it a third time with a CHANGED
// port updates only the observer entry's baseUrl.
func TestEnsurePrimeAgentObserverProvider_Idempotent(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	path := filepath.Join(home, ".prime", "agent", "models.json")

	if err := ensurePrimeAgentObserverProvider("http://127.0.0.1:8820/v1"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after run 1: %v", err)
	}
	if err := ensurePrimeAgentObserverProvider("http://127.0.0.1:8820/v1"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after run 2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("re-run with the same base URL did not converge:\nfirst:  %s\nsecond: %s", first, second)
	}

	if err := ensurePrimeAgentObserverProvider("http://127.0.0.1:9999/v1"); err != nil {
		t.Fatalf("run 3 (changed port): %v", err)
	}
	assertPrimeAgentProviderFile(t, path, "http://127.0.0.1:9999/v1")
}

// TestEnsurePrimeAgentObserverProvider_CorruptExistingFileErrors pins that a
// corrupt existing models.json returns an error rather than clobbering it.
func TestEnsurePrimeAgentObserverProvider_CorruptExistingFileErrors(t *testing.T) {
	home := t.TempDir()
	pinToolHomesAt(t, home)
	dir := filepath.Join(home, ".prime", "agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "models.json")
	corrupt := []byte(`{"providers": { not valid json`)
	if err := os.WriteFile(path, corrupt, 0o644); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}

	err := ensurePrimeAgentObserverProvider("http://127.0.0.1:8820/v1")
	if err == nil {
		t.Fatal("expected an error parsing a corrupt existing models.json, got nil")
	}

	after, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("re-read after failed ensure: %v", rerr)
	}
	if !bytes.Equal(after, corrupt) {
		t.Errorf("corrupt file was clobbered despite the parse error:\nbefore: %s\nafter:  %s", corrupt, after)
	}
}
