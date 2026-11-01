package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// useManagedHooks replaces the administrator hooks reader for one test. Not
// parallel: the reader is package state.
func useManagedHooks(t *testing.T, m map[string]ManagedHooks) {
	t.Helper()
	prev := managedHooksReader
	managedHooksReader = func(tool string) ManagedHooks { return m[tool] }
	t.Cleanup(func() { managedHooksReader = prev })
}

// TestManagedHooksDocument pins the administrator hooks files (IDE-5, the
// IDE-6 managed row): the catalogue path per OS, the per-node command text
// without --config, and a document that covers every event once parsed.
func TestManagedHooksDocument(t *testing.T) {
	cases := []struct {
		tool, binary, goos, path string
		wantKey, notKey          string
	}{
		{tool: "cursor", goos: "linux", path: "/etc/cursor/hooks.json", wantKey: `"version": 1`, notKey: "powershell"},
		{tool: "cursor", goos: "darwin", path: "/Library/Application Support/Cursor/hooks.json"},
		{tool: "cursor", goos: "windows", binary: `C:\Program Files\Observer\observer.exe`, path: `C:\ProgramData\Cursor\hooks.json`, wantKey: `"command": "'C:/Program Files/Observer/observer.exe' hook cursor`},
		{tool: "devin", goos: "linux", path: "/etc/devin/hooks.json", notKey: "powershell"},
		{tool: "devin", goos: "windows", binary: `C:\Program Files\Observer\observer.exe`, path: `C:\ProgramData\Devin\hooks.json`, wantKey: `"powershell": "\u0026 'C:\\Program Files\\Observer\\observer.exe' hook devin pre_user_prompt"`},
	}
	for _, tc := range cases {
		t.Run(tc.tool+"-"+tc.goos, func(t *testing.T) {
			doc, path, err := ManagedHooksDocument(tc.tool, tc.binary, tc.goos)
			if err != nil {
				t.Fatalf("ManagedHooksDocument: %v", err)
			}
			if path != tc.path {
				t.Errorf("path = %q, want %q", path, tc.path)
			}
			if tc.wantKey != "" && !strings.Contains(string(doc), tc.wantKey) {
				t.Errorf("document missing %s:\n%s", tc.wantKey, doc)
			}
			if tc.notKey != "" && strings.Contains(string(doc), tc.notKey) {
				t.Errorf("document carries %s:\n%s", tc.notKey, doc)
			}
			if strings.Contains(string(doc), "--config") {
				t.Errorf("a managed node's hook must read its default config:\n%s", doc)
			}
			spec, _ := managedHooksSpecFor(tc.tool)
			cov := ParseManagedHooksDocument(path, doc).Coverage(tc.tool, spec.events())
			if !cov.Complete() {
				t.Errorf("the generated file does not cover every event: missing %v", cov.Missing)
			}
		})
	}
	if _, _, err := ManagedHooksDocument("codex", "", "linux"); err == nil {
		t.Error("a tool with no administrator hooks file should be refused")
	}
}

// TestManagedHooksCoverage pins the ownership rule: only an Observer
// `hook <tool> <event>` command covers an event, and an untrusted file
// covers nothing.
func TestManagedHooksCoverage(t *testing.T) {
	doc := []byte(`{"version":1,"hooks":{"stop":[{"command":"/usr/bin/observer hook cursor stop"}],` +
		`"preToolUse":[{"command":"/opt/corp/audit.sh preToolUse"}],"sessionStart":[{"command":"observer hook cursor sessionEnd"}]}}`)
	m := ParseManagedHooksDocument("/etc/cursor/hooks.json", doc)
	cov := m.Coverage("cursor", []string{"stop", "preToolUse", "sessionStart"})
	if strings.Join(cov.Covered, ",") != "stop" || strings.Join(cov.Missing, ",") != "preToolUse,sessionStart" {
		t.Errorf("coverage = %+v, want only stop covered", cov)
	}
	m.Untrusted = "x"
	if cov := m.Coverage("cursor", []string{"stop"}); len(cov.Covered) != 0 {
		t.Errorf("an untrusted file covered %v", cov.Covered)
	}
	if bad := ParseManagedHooksDocument("p", []byte("[")); bad.Untrusted == "" {
		t.Error("a malformed file should be untrusted")
	}
}

// TestRegisterCursorStandsDownForEnterpriseHooks pins IDE-5: events the
// enterprise hooks.json already runs are not registered a second time.
func TestRegisterCursorStandsDownForEnterpriseHooks(t *testing.T) {
	full, _, err := ManagedHooksDocument("cursor", "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("complete", func(t *testing.T) {
		useManagedHooks(t, map[string]ManagedHooks{"cursor": ParseManagedHooksDocument("/etc/cursor/hooks.json", full)})
		r := setupRegistry(t)
		res := r.Register("cursor")
		if res.Error != nil || !res.CoveredElsewhere() {
			t.Fatalf("res = %+v, want SkipCovered", res)
		}
		if _, err := os.Stat(filepath.Join(r.opts.HomeDir, ".cursor", "hooks.json")); !os.IsNotExist(err) {
			t.Errorf("the user hooks.json was written under a complete enterprise file (err %v)", err)
		}
	})
	t.Run("partial", func(t *testing.T) {
		partial := []byte(`{"version":1,"hooks":{"stop":[{"command":"observer hook cursor stop"}]}}`)
		useManagedHooks(t, map[string]ManagedHooks{"cursor": ParseManagedHooksDocument("/etc/cursor/hooks.json", partial)})
		r := setupRegistry(t)
		res := r.Register("cursor")
		if res.Error != nil || res.Skipped {
			t.Fatalf("res = %+v", res)
		}
		if contains(res.HooksAdded, "stop") || len(res.HooksAdded) != len(cursorEvents)-1 {
			t.Errorf("HooksAdded = %v, want every event but stop", res.HooksAdded)
		}
		if len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "registered only") {
			t.Errorf("Warnings = %v, want the narrowing named", res.Warnings)
		}
	})
	t.Run("untrusted", func(t *testing.T) {
		m := ParseManagedHooksDocument("/etc/cursor/hooks.json", full)
		m.Untrusted = "/etc/cursor/hooks.json is writable by group or others"
		useManagedHooks(t, map[string]ManagedHooks{"cursor": m})
		r := setupRegistry(t)
		res := r.Register("cursor")
		if res.Error != nil || res.Skipped || len(res.HooksAdded) != len(cursorEvents) {
			t.Fatalf("res = %+v, want every event registered", res)
		}
		if len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "does not rely on it") {
			t.Errorf("Warnings = %v", res.Warnings)
		}
	})
	t.Run("force", func(t *testing.T) {
		useManagedHooks(t, map[string]ManagedHooks{"cursor": ParseManagedHooksDocument("/etc/cursor/hooks.json", full)})
		r := setupRegistry(t)
		r.opts.Force = true
		res := r.Register("cursor")
		if res.Error != nil || res.Skipped || len(res.HooksAdded) != len(cursorEvents) {
			t.Fatalf("res = %+v, want --force to register every event", res)
		}
	})
}

// TestRegisterCascadeStandsDownForSystemHooks pins the IDE-6 managed row.
func TestRegisterCascadeStandsDownForSystemHooks(t *testing.T) {
	full, _, err := ManagedHooksDocument("devin", "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	useManagedHooks(t, map[string]ManagedHooks{"devin": ParseManagedHooksDocument("/etc/devin/hooks.json", full)})
	r := setupRegistry(t)
	res := r.registerCascade()
	if res.Error != nil || !res.CoveredElsewhere() {
		t.Fatalf("res = %+v, want SkipCovered", res)
	}
	if _, err := os.Stat(filepath.Join(r.opts.HomeDir, ".codeium", "windsurf", "hooks.json")); !os.IsNotExist(err) {
		t.Errorf("the user Cascade hooks.json was written (err %v)", err)
	}
}

// TestReadManagedHooksFileTrust pins the trust rule: a file anyone could
// have written never stands Observer down.
func TestReadManagedHooksFileTrust(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hooks.json")
	doc, _, _ := ManagedHooksDocument("cursor", "", "linux")
	if err := os.WriteFile(p, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil { //nolint:gosec // G302: the test needs a world-writable file.
		t.Fatal(err)
	}
	m := readManagedHooksFile(p)
	if !m.Found || m.Untrusted == "" {
		t.Fatalf("m = %+v, want a found, untrusted file", m)
	}
	if missing := readManagedHooksFile(filepath.Join(dir, "absent.json")); missing.Found {
		t.Error("an absent file was found")
	}
	var probe map[string]any
	if err := json.Unmarshal(doc, &probe); err != nil {
		t.Fatal(err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestManagedHooksDropObserverDuplicates pins the audit follow-up to IDE-5
// and IDE-6: a trusted administrator file that runs Observer's hook for an
// event makes the per-node pass REMOVE Observer's own earlier entry for it
// (else both fire), never a non-Observer entry; a dry run writes nothing.
func TestManagedHooksDropObserverDuplicates(t *testing.T) {
	full, _, err := ManagedHooksDocument("cursor", "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	const foreign = "/opt/corp/audit.sh stop"
	seedCursor := func(t *testing.T, r *Registry) string {
		t.Helper()
		if res := r.Register("cursor"); res.Error != nil {
			t.Fatal(res.Error)
		}
		p := filepath.Join(r.opts.HomeDir, ".cursor", "hooks.json")
		var doc map[string]any
		b, _ := os.ReadFile(p)
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		hooks := doc["hooks"].(map[string]any)
		hooks["stop"] = append(hooks["stop"].([]any), map[string]any{"command": foreign})
		out, _ := json.Marshal(doc)
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("cursor: complete coverage removes every Observer entry, keeps the foreign one", func(t *testing.T) {
		r := setupRegistry(t)
		p := seedCursor(t, r)
		useManagedHooks(t, map[string]ManagedHooks{"cursor": ParseManagedHooksDocument("/etc/cursor/hooks.json", full)})
		res := r.Register("cursor")
		if res.Error != nil || !res.CoveredElsewhere() || len(res.HooksDropped) != len(cursorEvents) {
			t.Fatalf("res = %+v, want SkipCovered with every event dropped", res)
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "hook cursor") {
			t.Errorf("Observer per-node entries survived:\n%s", b)
		}
		if !strings.Contains(string(b), foreign) {
			t.Errorf("the foreign entry was removed:\n%s", b)
		}
		if !strings.Contains(res.SkipAdvice, "removed Observer's own per-node entries") {
			t.Errorf("SkipAdvice %q does not name the removal", res.SkipAdvice)
		}
	})
	t.Run("cursor: dry run reports and writes nothing", func(t *testing.T) {
		r := setupRegistry(t)
		p := seedCursor(t, r)
		before, _ := os.ReadFile(p)
		useManagedHooks(t, map[string]ManagedHooks{"cursor": ParseManagedHooksDocument("/etc/cursor/hooks.json", full)})
		r.opts.DryRun = true
		res := r.Register("cursor")
		if len(res.HooksDropped) != len(cursorEvents) || !strings.Contains(res.SkipAdvice, "would remove") {
			t.Fatalf("res = %+v", res)
		}
		if after, _ := os.ReadFile(p); string(after) != string(before) {
			t.Error("a dry run changed the file")
		}
	})
	t.Run("cursor: partial coverage drops only the covered event", func(t *testing.T) {
		r := setupRegistry(t)
		p := seedCursor(t, r)
		partial := []byte(`{"version":1,"hooks":{"stop":[{"command":"observer hook cursor stop"}]}}`)
		useManagedHooks(t, map[string]ManagedHooks{"cursor": ParseManagedHooksDocument("/etc/cursor/hooks.json", partial)})
		res := r.Register("cursor")
		if res.Error != nil || res.Skipped || strings.Join(res.HooksDropped, ",") != "stop" {
			t.Fatalf("res = %+v, want only stop dropped", res)
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "hook cursor stop") || !strings.Contains(string(b), "hook cursor preToolUse") || !strings.Contains(string(b), foreign) {
			t.Errorf("file after a partial stand-down:\n%s", b)
		}
	})
	t.Run("cascade: complete coverage removes Observer entries, keeps a foreign one", func(t *testing.T) {
		sys, _, err := ManagedHooksDocument("devin", "", "linux")
		if err != nil {
			t.Fatal(err)
		}
		r := setupRegistry(t)
		if res := r.registerCascade(); res.Error != nil {
			t.Fatal(res.Error)
		}
		p := filepath.Join(r.opts.HomeDir, ".codeium", "windsurf", "hooks.json")
		var doc map[string]any
		b, _ := os.ReadFile(p)
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatal(err)
		}
		h := doc["hooks"].(map[string]any)
		h["pre_user_prompt"] = append(h["pre_user_prompt"].([]any), map[string]any{"command": "/opt/corp/dlp.sh", "timeout": 5})
		out, _ := json.Marshal(doc)
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatal(err)
		}
		useManagedHooks(t, map[string]ManagedHooks{"devin": ParseManagedHooksDocument("/etc/devin/hooks.json", sys)})
		res := r.registerCascade()
		if res.Error != nil || !res.CoveredElsewhere() || len(res.HooksDropped) != len(cascadeEvents) {
			t.Fatalf("res = %+v", res)
		}
		b, _ = os.ReadFile(p)
		if strings.Contains(string(b), "hook devin") || !strings.Contains(string(b), "/opt/corp/dlp.sh") || !strings.Contains(string(b), `"timeout"`) {
			t.Errorf("Cascade file after the stand-down:\n%s", b)
		}
	})
}
