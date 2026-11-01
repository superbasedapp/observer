package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPiRouteFor pins the routing table. The regression: `observer pi` with no
// --model prepended `--provider observer` alone and pi 1.0 refused to start
// ("--provider requires --model").
func TestPiRouteFor(t *testing.T) {
	served := piObserverModelIDs()
	cases := []struct {
		name         string
		in           piRouteInputs
		wantArgs     []string
		wantRouted   bool
		noticeHas    []string
		wantNoNotice bool
	}{
		{
			// Never switch the developer's model behind their back (A5-08's
			// rule): pi runs UNROUTED on its own default, and says so.
			name:      "no model, pi default on another provider -> unrouted on that default, said out loud",
			in:        piRouteInputs{args: []string{"fix the bug"}, defaultProvider: "baseten", defaultModel: "zai-org/GLM-5.2", providerModels: served},
			wantArgs:  []string{"fix the bug"},
			noticeHas: []string{"not routed through Observer", "your default model zai-org/GLM-5.2 is on baseten", "pass --model <an OpenAI model> to route", "gpt-4o"},
		},
		{
			name:      "no model, pi default model with no provider named, not served -> unrouted",
			in:        piRouteInputs{defaultModel: "zai-org/GLM-5.2", providerModels: served},
			wantArgs:  nil,
			noticeHas: []string{"not routed through Observer", "zai-org/GLM-5.2", "pass --model <an OpenAI model> to route"},
		},
		{
			name:       "no model, pi default provider but no default model -> observer default, said out loud",
			in:         piRouteInputs{defaultProvider: "baseten", providerModels: served},
			wantArgs:   []string{"--provider", "observer", "--model", "gpt-4o"},
			wantRouted: true,
			noticeHas:  []string{"pi has no default model configured", "gpt-4o"},
		},
		{
			name:         "no model, pi default served by the observer provider -> that default",
			in:           piRouteInputs{args: []string{"fix the bug"}, defaultProvider: "openai", defaultModel: "gpt-4o-mini", providerModels: served},
			wantArgs:     []string{"--provider", "observer", "--model", "gpt-4o-mini", "fix the bug"},
			wantRouted:   true,
			wantNoNotice: true,
		},
		{
			name:       "no model, no pi default -> observer default",
			in:         piRouteInputs{providerModels: served},
			wantArgs:   []string{"--provider", "observer", "--model", "gpt-4o"},
			wantRouted: true,
			noticeHas:  []string{"pi has no default model configured", "gpt-4o"},
		},
		{
			name:         "operator model -> provider only",
			in:           piRouteInputs{args: []string{"--model", "gpt-4o-mini", "-p", "hi"}, defaultModel: "zai-org/GLM-5.2", providerModels: served},
			wantArgs:     []string{"--provider", "observer", "--model", "gpt-4o-mini", "-p", "hi"},
			wantRouted:   true,
			wantNoNotice: true,
		},
		{
			name:         "operator already selected observer and a model -> untouched",
			in:           piRouteInputs{args: []string{"--provider", "observer", "--model", "gpt-4o"}, providerModels: served},
			wantArgs:     []string{"--provider", "observer", "--model", "gpt-4o"},
			wantRouted:   true,
			wantNoNotice: true,
		},
		{
			name:       "operator selected observer without a model -> model added, provider not duplicated",
			in:         piRouteInputs{args: []string{"--provider", "observer"}, providerModels: served},
			wantArgs:   []string{"--model", "gpt-4o", "--provider", "observer"},
			wantRouted: true,
			noticeHas:  []string{"gpt-4o"},
		},
		{
			name:       "operator selected observer, pi default unserved -> observer default (their explicit choice), said out loud",
			in:         piRouteInputs{args: []string{"--provider", "observer"}, defaultProvider: "baseten", defaultModel: "zai-org/GLM-5.2", providerModels: served},
			wantArgs:   []string{"--model", "gpt-4o", "--provider", "observer"},
			wantRouted: true,
			noticeHas:  []string{"observer provider you selected", "gpt-4o"},
		},
		{
			name:      "foreign provider -> untouched, not routed",
			in:        piRouteInputs{args: []string{"--provider", "anthropic", "--model", "claude-x"}, providerModels: served},
			wantArgs:  []string{"--provider", "anthropic", "--model", "claude-x"},
			noticeHas: []string{"--provider anthropic", "NOT proxy-routed"},
		},
		{
			name:      "blank model -> untouched, not routed",
			in:        piRouteInputs{args: []string{"--model", ""}, defaultModel: "gpt-4o", providerModels: served},
			wantArgs:  []string{"--model", ""},
			noticeHas: []string{"EMPTY --model"},
		},
		{
			name:      "no configured observer models -> untouched, told",
			in:        piRouteInputs{args: []string{"hi"}},
			wantArgs:  []string{"hi"},
			noticeHas: []string{"NOT proxy-routed"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := piRouteFor(tc.in)
			if strings.Join(got.args, "\x00") != strings.Join(tc.wantArgs, "\x00") {
				t.Errorf("args = %q, want %q", got.args, tc.wantArgs)
			}
			if got.routed != tc.wantRouted {
				t.Errorf("routed = %v, want %v", got.routed, tc.wantRouted)
			}
			if tc.wantNoNotice && got.notice != "" {
				t.Errorf("unexpected notice %q", got.notice)
			}
			for _, s := range tc.noticeHas {
				if !strings.Contains(got.notice, s) {
					t.Errorf("notice %q lacks %q", got.notice, s)
				}
			}
			// pi's own rule: whenever the observer provider is selected, a
			// non-empty model must be too.
			if p := piFlagValue(got.args, "--provider"); p.present && p.value == piProviderName {
				if m := piFlagValue(got.args, "--model"); strings.TrimSpace(m.value) == "" {
					t.Errorf("args %q select the observer provider without a model", got.args)
				}
			}
		})
	}
}

// runPiLauncherWithSettings drives the real `observer pi` command against a
// fake pi that enforces pi 1.0's rule ("--provider requires --model"), with
// pi's settings.json holding settings ("" = no settings file). It returns the
// argv the fake pi received and the launcher's combined output.
func runPiLauncherWithSettings(t *testing.T, settings string) ([]string, string) {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	// A key for the session-scoped observer provider (Sol A5-08): without one
	// the launcher writes no provider and starts pi unrouted before the
	// model-routing decision is ever reached.
	t.Setenv(observerProviderAPIKeyEnv, "test-not-a-secret")
	agentDir := filepath.Join(home, ".pi", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if settings != "" {
		if err := os.WriteFile(filepath.Join(agentDir, "settings.json"), []byte(settings), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "argv.txt")
	bin := filepath.Join(dir, "pi")
	script := "#!/bin/sh\n: > " + stubShPath(argsFile) + "\nprov=; model=\n" +
		"while [ $# -gt 0 ]; do printf '%s\\n' \"$1\" >> " + stubShPath(argsFile) + "\n" +
		"  case \"$1\" in --provider) prov=1;; --model) model=$2;; esac; shift; done\n" +
		"if [ -n \"$prov\" ] && [ -z \"$model\" ]; then echo 'Error: --provider requires --model' >&2; exit 1; fi\nexit 0\n"
	bin = writeShellStub(t, bin, script)

	cmd := newPiCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"--config", codexArgvTempConfig(t), "--pi-path", bin,
		"--proxy-url", closedProxyURL(t), "--no-attach",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("observer pi failed: %v (output %q)", err, out.String())
	}
	return codexRecordedArgv(t, argsFile), out.String()
}

// TestPiLauncherBareLaunchPassesAModel: with no pi default model configured,
// a bare launch routes on the observer provider's default and says so. Before
// the fix the launcher forwarded `--provider observer` alone and the fake
// refused, exactly as on demo node 1.
func TestPiLauncherBareLaunchPassesAModel(t *testing.T) {
	got, out := runPiLauncherWithSettings(t, `{"defaultProvider":"baseten"}`)
	if !argvHasPair(got, "--provider", piProviderName) || !argvHasPair(got, "--model", "gpt-4o") {
		t.Fatalf("pi argv = %v, want --provider observer --model gpt-4o", got)
	}
	if !strings.Contains(out, "pi has no default model configured") || !strings.Contains(out, "gpt-4o") {
		t.Errorf("the operator was not told which model was chosen and why: %q", out)
	}
}

// TestPiLauncherKeepsTheDevelopersOwnDefaultModel: a pi default model on a
// provider the observer provider does not serve is never swapped out. pi runs
// UNROUTED on it (no --provider/--model injected) and a notice says how to
// route (A5-08's rule: a collision launches unrouted, never a substitute).
func TestPiLauncherKeepsTheDevelopersOwnDefaultModel(t *testing.T) {
	got, out := runPiLauncherWithSettings(t, `{"defaultProvider":"baseten","defaultModel":"zai-org/GLM-5.2"}`)
	for _, a := range got {
		if a == "--provider" || a == "--model" {
			t.Fatalf("pi argv = %v, want the developer's own default left alone (no --provider/--model)", got)
		}
	}
	want := "not routed through Observer: your default model zai-org/GLM-5.2 is on baseten"
	if !strings.Contains(out, want) {
		t.Errorf("output %q lacks %q", out, want)
	}
}

func TestReadPiDefaults(t *testing.T) {
	dir := t.TempDir()
	if p, m := readPiDefaults(dir); p != "" || m != "" {
		t.Errorf("missing settings = %q %q, want empty", p, m)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"),
		[]byte(`{"lastChangelogVersion":"1.0.0","defaultProvider":"baseten","defaultModel":" zai-org/GLM-5.2 "}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, m := readPiDefaults(dir); p != "baseten" || m != "zai-org/GLM-5.2" {
		t.Errorf("defaults = %q %q", p, m)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, m := readPiDefaults(dir); p != "" || m != "" {
		t.Errorf("corrupt settings = %q %q, want empty", p, m)
	}
	if p, m := readPiDefaults(""); p != "" || m != "" {
		t.Errorf("no agent dir = %q %q, want empty", p, m)
	}
}

func TestPiFlagValueMatchesPiParser(t *testing.T) {
	cases := []struct {
		args    []string
		present bool
		value   string
	}{
		{[]string{"--model", "a", "--model", "b"}, true, "b"}, // last wins
		{[]string{"--models", "a,b"}, false, ""},              // a different flag
		{[]string{"--model=a"}, false, ""},                    // pi has no = form
		{[]string{"--model"}, true, ""},
		{[]string{"--", "--model", "a"}, false, ""},
	}
	for _, tc := range cases {
		f := piFlagValue(tc.args, "--model")
		if f.present != tc.present || f.value != tc.value {
			t.Errorf("piFlagValue(%q) = %+v, want {%v %q}", tc.args, f, tc.present, tc.value)
		}
	}
}
