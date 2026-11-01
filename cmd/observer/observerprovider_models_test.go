package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Sol A5-08: the pi / prime-agent launchers used to overwrite any provider
// named "observer" (destroying the operator's own entry of that name), write
// it even when no key could resolve (a keyless launch that fails on its first
// prompt), and never remove it. These pin the session-scoped replacement.

func TestDecideObserverModelsRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state observerModelsState
		want  observerModelsAction
	}{
		{"no credential for the provider", observerModelsState{hasCredential: false}, observerModelsNoCredential},
		{"no credential beats a collision", observerModelsState{hasCredential: false, foreignEntry: true}, observerModelsNoCredential},
		{"the operator's own provider has our name", observerModelsState{hasCredential: true, foreignEntry: true}, observerModelsCollision},
		{"route through the session provider", observerModelsState{hasCredential: true}, observerModelsWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideObserverModels(tc.state); got != tc.want {
				t.Fatalf("decideObserverModels(%+v) = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}

func testModelsSpec(path string, hasCredential bool) observerModelsProviderSpec {
	return observerModelsProviderSpec{
		tool: "pi", path: path, display: "~/.pi/agent/models.json", name: "observer",
		baseURL: "http://127.0.0.1:8820/v1",
		models:  []any{piModel("gpt-4o", "gpt-4o (observer proxy)")}, hasCredential: hasCredential,
	}
}

func TestObserverModelsProviderNeverOverwritesTheOperatorsOwn(t *testing.T) {
	for name, entry := range map[string]string{
		"own gateway":              `{"baseUrl":"https://llm-gateway.corp.example/v1","api":"openai-completions","apiKey":"OPENAI_API_KEY","models":[{"id":"custom"}]}`,
		"own key variable":         `{"baseUrl":"http://127.0.0.1:8820/v1","api":"openai-completions","apiKey":"MY_KEY","models":[]}`,
		"another API":              `{"baseUrl":"http://127.0.0.1:8820/v1","api":"anthropic-messages","apiKey":"OPENAI_API_KEY"}`,
		"not an object":            `"something"`,
		"local but not a /v1 path": `{"baseUrl":"http://localhost:11434","api":"openai-completions","apiKey":"OPENAI_API_KEY"}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "models.json")
			body := `{"providers":{"observer":` + entry + `,"ollama":{"baseUrl":"http://localhost:11434/v1"}}}`
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			route, err := prepareObserverModelsProvider(testModelsSpec(path, true))
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if route.routed || route.restore != nil || !strings.Contains(route.note, "will not overwrite") {
				t.Fatalf("route = %+v; want unrouted with a collision note and nothing to restore", route)
			}
			if got, _ := os.ReadFile(path); string(got) != body {
				t.Errorf("the operator's provider was rewritten:\n%s", got)
			}
		})
	}
}

func TestObserverModelsProviderWithoutACredentialWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent", "models.json")
	route, err := prepareObserverModelsProvider(testModelsSpec(path, false))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if route.routed || route.restore != nil || !strings.Contains(route.note, "OPENAI_API_KEY is not set") {
		t.Fatalf("route = %+v; want unrouted with the missing-key note", route)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a keyless launch wrote models.json (stat err %v)", err)
	}
}

func TestObserverModelsProviderIsRemovedAfterTheSession(t *testing.T) {
	t.Run("created file is removed again", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent", "models.json")
		route, err := prepareObserverModelsProvider(testModelsSpec(path, true))
		if err != nil || !route.routed || route.restore == nil {
			t.Fatalf("route = %+v err = %v; want routed with a restore", route, err)
		}
		var root map[string]any
		data, _ := os.ReadFile(path)
		if err := json.Unmarshal(data, &root); err != nil {
			t.Fatalf("written file: %v", err)
		}
		entry := root["providers"].(map[string]any)["observer"].(map[string]any)
		if entry["apiKey"] != "OPENAI_API_KEY" || bytes.Contains(data, []byte("sk-")) {
			t.Fatalf("written entry %v must carry only the env var NAME", entry)
		}
		if err := route.restore(); err != nil {
			t.Fatalf("restore: %v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a file this launch created survived the session (stat err %v)", err)
		}
	})
	t.Run("existing file keeps everything else", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "models.json")
		body := `{"defaultProvider":"ollama","providers":{"ollama":{"baseUrl":"http://localhost:11434/v1"}}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		route, err := prepareObserverModelsProvider(testModelsSpec(path, true))
		if err != nil || route.restore == nil {
			t.Fatalf("route = %+v err = %v", route, err)
		}
		if err := route.restore(); err != nil {
			t.Fatalf("restore: %v", err)
		}
		var root map[string]any
		data, _ := os.ReadFile(path)
		if err := json.Unmarshal(data, &root); err != nil {
			t.Fatal(err)
		}
		providers := root["providers"].(map[string]any)
		if _, ok := providers["observer"]; ok || providers["ollama"] == nil || root["defaultProvider"] != "ollama" {
			t.Errorf("after restore = %s", data)
		}
	})
	t.Run("an edit made during the session wins", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "models.json")
		route, err := prepareObserverModelsProvider(testModelsSpec(path, true))
		if err != nil || route.restore == nil {
			t.Fatalf("route = %+v err = %v", route, err)
		}
		edited := `{"providers":{"observer":{"baseUrl":"http://127.0.0.1:8820/v1","api":"openai-completions","apiKey":"OPENAI_API_KEY","models":[{"id":"their-model"}]}}}`
		if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := route.restore(); err != nil {
			t.Fatalf("restore: %v", err)
		}
		if got, _ := os.ReadFile(path); string(got) != edited {
			t.Errorf("restore removed an entry edited during the session:\n%s", got)
		}
	})
}

func TestLauncherHasOpenAIKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		args []string
		want bool
	}{
		{"env set", "k", nil, true},
		{"env blank", "  ", nil, false},
		{"nothing", "", []string{"--model", "gpt-4o"}, false},
		{"--api-key value", "", []string{"--api-key", "k"}, true},
		{"--api-key=value", "", []string{"--api-key=k"}, true},
		{"--api-key with no value", "", []string{"--api-key"}, false},
		{"--api-key= empty", "", []string{"--api-key="}, false},
		{"after -- is a message, not a flag", "", []string{"--", "--api-key", "k"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(observerProviderAPIKeyEnv, tc.env)
			if got := launcherHasOpenAIKey(tc.args); got != tc.want {
				t.Errorf("launcherHasOpenAIKey(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// piLauncherRun executes `observer pi` against a stub that records its argv
// and copies models.json as it saw it during the session.
func piLauncherRun(t *testing.T, home string, args ...string) (argv []string, during string, stderr string, err error) {
	t.Helper()
	originalRuntimeDir := agentRuntimeDir
	originalLoginPathDirs := daemonLoginPathDirs
	agentRuntimeDir = func() string { return "" }
	daemonLoginPathDirs = func() []string { return nil }
	t.Cleanup(func() {
		agentRuntimeDir = originalRuntimeDir
		daemonLoginPathDirs = originalLoginPathDirs
	})
	setTestHome(t, home)
	dir := t.TempDir()
	cfgPath := writeCopilotCLITestConfig(t, dir)
	argvPath := filepath.Join(dir, "argv.out")
	duringPath := filepath.Join(dir, "during.json")
	models := filepath.Join(home, ".pi", "agent", "models.json")
	stub := filepath.Join(dir, "stub-pi.sh")
	script := "#!/bin/sh\n" +
		"touch " + shellQuote(stubShPath(argvPath)) + "\n" +
		"for a in \"$@\"; do printf '%s\\n' \"$a\" >> " + shellQuote(stubShPath(argvPath)) + "; done\n" +
		"[ -f " + shellQuote(stubShPath(models)) + " ] && cp " + shellQuote(stubShPath(models)) + " " + shellQuote(stubShPath(duringPath)) + "\n" +
		"exit 0\n"
	stub = writeShellStub(t, stub, script)
	output := new(bytes.Buffer)
	root := &cobra.Command{Use: "observer", SilenceUsage: true}
	root.AddCommand(newPiCmd())
	root.SetArgs(append([]string{"pi", "--config", cfgPath, "--pi-path", stub, "--no-attach", "--proxy-url", "http://127.0.0.1:1"}, args...))
	root.SetOut(output)
	root.SetErr(output)
	executed, err := root.ExecuteC()
	renderSuppressedLauncherError(output, root, executed, err)
	if _, statErr := os.Stat(argvPath); statErr == nil {
		argv = readRecordedArgv(t, argvPath)
	}
	if data, rerr := os.ReadFile(duringPath); rerr == nil {
		during = string(data)
	}
	return argv, during, output.String(), err
}

func TestPiLauncherRoutesForTheSessionOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv(observerProviderAPIKeyEnv, "test-not-a-secret")
	argv, during, stderr, err := piLauncherRun(t, home)
	if err != nil {
		t.Fatalf("launch: %v\n%s", err, stderr)
	}
	// With no pi default model, the routing table (pi_route.go) pairs the
	// provider with its own default model: pi 1.0 refuses --provider alone.
	if want := []string{"--provider", piProviderName, "--model", piObserverModelIDs()[0]}; !equalArgs(argv, want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	if !strings.Contains(during, `"baseUrl": "http://127.0.0.1:1/v1"`) {
		t.Errorf("models.json during the session = %q, want the observer provider", during)
	}
	if _, err := os.Stat(filepath.Join(home, ".pi", "agent", "models.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the session provider survived pi's exit (stat err %v)", err)
	}
}

// argvHasProviderOrModel reports whether the launcher injected a provider or
// model selection into pi's argv.
func argvHasProviderOrModel(argv []string) bool {
	for _, a := range argv {
		if a == "--provider" || a == "--model" {
			return true
		}
	}
	return false
}

// TestPiLauncherUnroutedPathsInjectNothing pins the integration of A5-08 (the
// session-scoped provider decision) with the pi routing table (pi_route.go):
// `--provider observer --model <m>` appears ONLY when the provider is in place
// and the table routes. A collision with the operator's own `observer`
// provider and a launch with no key both start pi on its own selection, with
// the A5-08 note and without ever reaching the routing table's notice.
func TestPiLauncherUnroutedPathsInjectNothing(t *testing.T) {
	ownProvider := `{"providers":{"observer":{"baseUrl":"https://llm-gateway.corp.example/v1","api":"openai-completions","apiKey":"OPENAI_API_KEY","models":[{"id":"custom"}]}}}`
	tests := []struct {
		name     string
		key      string
		models   string // pre-existing ~/.pi/agent/models.json ("" = none)
		wantNote string
		wantKeep bool // models.json must be byte-identical afterwards
	}{
		{name: "collision with the operator's own provider", key: "test-not-a-secret", models: ownProvider, wantNote: "will not overwrite", wantKeep: true},
		{name: "no key, bare launch", key: "", wantNote: "NOT routing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv(observerProviderAPIKeyEnv, tc.key)
			path := filepath.Join(home, ".pi", "agent", "models.json")
			if tc.models != "" {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.models), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			argv, _, stderr, err := piLauncherRun(t, home)
			if err != nil {
				t.Fatalf("launch: %v\n%s", err, stderr)
			}
			if argvHasProviderOrModel(argv) {
				t.Fatalf("argv = %v, want no --provider/--model on an unrouted path", argv)
			}
			if !strings.Contains(stderr, tc.wantNote) {
				t.Errorf("stderr %q lacks the A5-08 note %q", stderr, tc.wantNote)
			}
			if strings.Contains(stderr, "pi has no default model configured") {
				t.Errorf("stderr %q: the routing table ran on an unrouted path", stderr)
			}
			if tc.wantKeep {
				if got, _ := os.ReadFile(path); string(got) != tc.models {
					t.Errorf("the operator's models.json was rewritten:\n%s", got)
				}
			}
		})
	}
}

func TestPiLauncherWithoutAKeyStartsUnrouted(t *testing.T) {
	home := t.TempDir()
	t.Setenv(observerProviderAPIKeyEnv, "")
	argv, during, stderr, err := piLauncherRun(t, home, "--", "--model", "m")
	if err != nil {
		t.Fatalf("launch: %v\n%s", err, stderr)
	}
	if want := []string{"--model", "m"}; !equalArgs(argv, want) {
		t.Fatalf("argv = %v, want %v (no --provider observer without a key)", argv, want)
	}
	if during != "" || !strings.Contains(stderr, "NOT routing") || strings.Contains(stderr, "routing via") {
		t.Errorf("during=%q stderr=%q; want no provider written and only the not-routed note", during, stderr)
	}
}
