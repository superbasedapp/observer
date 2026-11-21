//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHostedInBoxToolKeys (decision SBXD-4 (b)): an in-box run opted in to
// OpenCode's own saved keys gets the API key entries of its auth.json (never
// an OAuth entry) in variables the environment left empty, read once per
// run; a home_relay run or a run not opted in gets none.
func TestHostedInBoxToolKeys(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".local", "share", "opencode")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := `{"openai":{"type":"api","key":"sk-saved-openai"},"anthropic":{"type":"oauth","refresh":"r","access":"a","expires":1}}`
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := hostedToolKeysHome
	hostedToolKeysHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { hostedToolKeysHome = prev })
	hostedTestEnv(t, map[string]string{})

	plan := hostedPlanFile{RunID: "run-toolkeys-1", Tool: "opencode", Custody: "in_box_api_key", ToolKeys: true}
	t.Cleanup(func() { hostedToolKeysCache.Delete(plan.RunID) })
	env := map[string]string{"GEMINI_API_KEY": "from-env"}
	hostedInBoxToolKeys(plan, env)
	if env["OPENAI_API_KEY"] != "sk-saved-openai" || env["ANTHROPIC_API_KEY"] != "" || env["GEMINI_API_KEY"] != "from-env" {
		t.Fatalf("env %v", env)
	}
	// Read once per run: the file changing does not change this run.
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), []byte(`{"openai":{"type":"api","key":"other"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	again := map[string]string{}
	hostedInBoxToolKeys(plan, again)
	if again["OPENAI_API_KEY"] != "sk-saved-openai" {
		t.Fatalf("second read %v", again)
	}
	// A variable already filled (the environment or a stored key) wins.
	kept := map[string]string{"OPENAI_API_KEY": "stored"}
	hostedInBoxToolKeys(plan, kept)
	if kept["OPENAI_API_KEY"] != "stored" {
		t.Fatalf("a filled variable was replaced: %v", kept)
	}
	for _, p := range []hostedPlanFile{
		{RunID: "run-toolkeys-2", Tool: "opencode", Custody: "home_relay", ToolKeys: true},
		{RunID: "run-toolkeys-3", Tool: "opencode", Custody: "in_box_api_key"},
		{RunID: "run-toolkeys-4", Tool: "droid", Custody: "in_box_api_key", ToolKeys: true},
	} {
		e := map[string]string{}
		hostedInBoxToolKeys(p, e)
		hostedToolKeysCache.Delete(p.RunID)
		if len(e) != 0 {
			t.Errorf("%+v: %v", p, e)
		}
	}
}
