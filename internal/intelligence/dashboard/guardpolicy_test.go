package dashboard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// validUserPolicy is a policy that lints clean: one user rule + one
// built-in override.
const validUserPolicy = `[[rule]]
id = "U-001"
category = "destructive"
severity = "high"
decision = "ask"
applies_to = ["shell_exec"]
match.command_regex = '(?i)\bpulumi\s+(up|destroy)\b'

[[override]]
rule = "R-110"
decision = "deny"
`

// validUserPolicyV2 is a distinct second version so backup-swap
// assertions can tell the files apart.
const validUserPolicyV2 = `[[override]]
rule = "R-101"
enforce = true
`

// newGuardPolicyServer builds a server whose on-disk config points
// the guard's user policy INSIDE the test dir — these tests write
// real files and must never touch the operator's ~/.observer (the
// internal/hook test-isolation leak is the cautionary tale).
func newGuardPolicyServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	tdir := t.TempDir()
	policyPath := filepath.Join(tdir, "guard-policy.toml")
	cfgPath := filepath.Join(tdir, "config.toml")
	cfgToml := "[guard]\nenabled = true\nmode = \"observe\"\n" +
		"[guard.rules]\nuser_policy = '" + filepath.ToSlash(policyPath) + "'\n"
	if err := os.WriteFile(cfgPath, []byte(cfgToml), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	return server, policyPath, tdir
}

func doGuardPolicy(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func policyBody(content string) string {
	b, _ := json.Marshal(map[string]string{"content": content})
	return string(b)
}

// TestAPIGuardPolicy pins the G2.2 editor contract end to end: the
// lint gate refuses a malformed save with 422 (file untouched), a
// clean save lands atomically with the prior version kept at .bak,
// and the GET view reports the user layer's path/content/counts.
func TestAPIGuardPolicy(t *testing.T) {
	t.Parallel()
	s, policyPath, _ := newGuardPolicyServer(t)

	// Fresh install: no policy file yet, but the path is writable.
	rec := doGuardPolicy(t, s, "GET", "/api/guard/policy", "")
	if rec.Code != 200 {
		t.Fatalf("GET status = %d: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		User struct {
			Path     string `json:"path"`
			Exists   bool   `json:"exists"`
			Writable bool   `json:"writable"`
		} `json:"user"`
		Layers []struct {
			Layer    string `json:"layer"`
			Editable bool   `json:"editable"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	if view.User.Exists || !view.User.Writable {
		t.Errorf("fresh view user = %+v, want exists=false writable=true", view.User)
	}
	if filepath.Clean(view.User.Path) != filepath.Clean(policyPath) {
		t.Errorf("user path = %q, want %q", view.User.Path, policyPath)
	}

	// Malformed save → 422 with problems; nothing lands on disk.
	rec = doGuardPolicy(t, s, "PUT", "/api/guard/policy", policyBody("[[rule]]\nid = 'U-1'\nmatch.bogus = true\n"))
	if rec.Code != 422 {
		t.Fatalf("malformed PUT status = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	var lintResp struct {
		Saved    bool     `json:"saved"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lintResp); err != nil {
		t.Fatalf("decode 422: %v", err)
	}
	if lintResp.Saved || len(lintResp.Problems) == 0 {
		t.Errorf("422 body = %+v, want saved=false with problems", lintResp)
	}
	if _, err := os.Stat(policyPath); !os.IsNotExist(err) {
		t.Errorf("malformed PUT left a file at %s", policyPath)
	}

	// Clean save → file on disk, counts reported, restart-honest.
	rec = doGuardPolicy(t, s, "PUT", "/api/guard/policy", policyBody(validUserPolicy))
	if rec.Code != 200 {
		t.Fatalf("PUT status = %d: %s", rec.Code, rec.Body.String())
	}
	var saveResp struct {
		Saved           bool `json:"saved"`
		Rules           int  `json:"rules"`
		Overrides       int  `json:"overrides"`
		RestartRequired bool `json:"restart_required"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saveResp); err != nil {
		t.Fatalf("decode save: %v", err)
	}
	if !saveResp.Saved || saveResp.Rules != 1 || saveResp.Overrides != 1 || !saveResp.RestartRequired {
		t.Errorf("save resp = %+v, want saved 1 rule / 1 override / restart_required", saveResp)
	}
	onDisk, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read saved policy: %v", err)
	}
	if string(onDisk) != validUserPolicy {
		t.Errorf("on-disk policy drifted: %q", onDisk)
	}

	// Second save keeps the prior version at .bak.
	rec = doGuardPolicy(t, s, "PUT", "/api/guard/policy", policyBody(validUserPolicyV2))
	if rec.Code != 200 {
		t.Fatalf("second PUT status = %d: %s", rec.Code, rec.Body.String())
	}
	bak, err := os.ReadFile(policyPath + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if string(bak) != validUserPolicy {
		t.Errorf(".bak = %q, want the first version", bak)
	}

	// The view now resolves the user layer with content + counts.
	rec = doGuardPolicy(t, s, "GET", "/api/guard/policy", "")
	var view2 struct {
		User struct {
			Exists       bool   `json:"exists"`
			Content      string `json:"content"`
			BackupExists bool   `json:"backup_exists"`
		} `json:"user"`
		Layers []struct {
			Layer     string   `json:"layer"`
			Editable  bool     `json:"editable"`
			Rules     int      `json:"rules"`
			Overrides int      `json:"overrides"`
			Problems  []string `json:"problems"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view2); err != nil {
		t.Fatalf("decode view2: %v", err)
	}
	if !view2.User.Exists || view2.User.Content != validUserPolicyV2 || !view2.User.BackupExists {
		t.Errorf("view2 user = %+v, want exists + v2 content + backup", view2.User)
	}
	foundUser := false
	for _, l := range view2.Layers {
		if l.Layer == "user" {
			foundUser = true
			if !l.Editable || l.Rules != 0 || l.Overrides != 1 || len(l.Problems) != 0 {
				t.Errorf("user layer row = %+v, want editable / 0 rules / 1 override / clean", l)
			}
		}
	}
	if !foundUser {
		t.Error("layers missing the user row")
	}

	// Swap-undo: restore brings v1 back and parks v2 in .bak; a
	// second restore undoes the first.
	rec = doGuardPolicy(t, s, "POST", "/api/guard/policy/backup", "")
	if rec.Code != 200 {
		t.Fatalf("restore status = %d: %s", rec.Code, rec.Body.String())
	}
	onDisk, _ = os.ReadFile(policyPath)
	bak, _ = os.ReadFile(policyPath + ".bak")
	if string(onDisk) != validUserPolicy || string(bak) != validUserPolicyV2 {
		t.Errorf("after restore: file=%q bak=%q, want v1/v2 swapped", onDisk, bak)
	}
	rec = doGuardPolicy(t, s, "POST", "/api/guard/policy/backup", "")
	if rec.Code != 200 {
		t.Fatalf("second restore status = %d: %s", rec.Code, rec.Body.String())
	}
	onDisk, _ = os.ReadFile(policyPath)
	if string(onDisk) != validUserPolicyV2 {
		t.Errorf("second restore did not undo the first: %q", onDisk)
	}
}

// TestAPIGuardPolicyLint pins the validate endpoint: same checker as
// the save gate, 200 either way, closed layer vocabulary.
func TestAPIGuardPolicyLint(t *testing.T) {
	t.Parallel()
	s, _, _ := newGuardPolicyServer(t)

	body, _ := json.Marshal(map[string]string{"content": validUserPolicy})
	rec := doGuardPolicy(t, s, "POST", "/api/guard/policy/lint", string(body))
	if rec.Code != 200 {
		t.Fatalf("lint status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK        bool     `json:"ok"`
		Problems  []string `json:"problems"`
		Rules     int      `json:"rules"`
		Overrides int      `json:"overrides"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || len(resp.Problems) != 0 || resp.Rules != 1 || resp.Overrides != 1 {
		t.Errorf("clean lint = %+v, want ok with 1 rule / 1 override", resp)
	}

	body, _ = json.Marshal(map[string]string{"content": "[[override]]\nrule = 'R-999'\n"})
	rec = doGuardPolicy(t, s, "POST", "/api/guard/policy/lint", string(body))
	if rec.Code != 200 {
		t.Fatalf("lint status = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.OK || len(resp.Problems) == 0 {
		t.Errorf("unknown-override lint = %+v, want problems", resp)
	}

	// A project-layer relaxation lints dirty under layer=project (the
	// §4.6 one-way check) — the layer param is load-bearing.
	relaxing := "[[override]]\nrule = \"R-110\"\ndecision = \"allow\"\n"
	body, _ = json.Marshal(map[string]string{"content": relaxing, "layer": "project"})
	rec = doGuardPolicy(t, s, "POST", "/api/guard/policy/lint", string(body))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.OK {
		t.Errorf("project-layer relaxation linted clean: %+v", resp)
	}

	body, _ = json.Marshal(map[string]string{"content": "", "layer": "bogus"})
	rec = doGuardPolicy(t, s, "POST", "/api/guard/policy/lint", string(body))
	if rec.Code != 400 {
		t.Errorf("bogus layer status = %d, want 400", rec.Code)
	}
	rec = doGuardPolicy(t, s, "GET", "/api/guard/policy/lint", "")
	if rec.Code != 405 {
		t.Errorf("GET lint status = %d, want 405", rec.Code)
	}
}

// TestAPIGuardPolicyProjectLayer pins the read-only project view: a
// known project root carrying the configured relative policy path
// shows up in layers with counts, NOT editable.
func TestAPIGuardPolicyProjectLayer(t *testing.T) {
	t.Parallel()
	s, _, tdir := newGuardPolicyServer(t)

	root := filepath.Join(tdir, "proj")
	if err := os.MkdirAll(filepath.Join(root, ".observer"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Escalation-only content — a project layer may not relax (§4.6).
	projPolicy := "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n"
	if err := os.WriteFile(filepath.Join(root, ".observer", "guard-policy.toml"), []byte(projPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.New(s.opts.DB).UpsertProject(context.Background(), root, ""); err != nil {
		t.Fatal(err)
	}

	rec := doGuardPolicy(t, s, "GET", "/api/guard/policy", "")
	if rec.Code != 200 {
		t.Fatalf("GET status = %d: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		Layers []struct {
			Layer       string   `json:"layer"`
			Editable    bool     `json:"editable"`
			Overrides   int      `json:"overrides"`
			Problems    []string `json:"problems"`
			ProjectRoot string   `json:"project_root"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, l := range view.Layers {
		if l.Layer == "project" && filepath.Clean(l.ProjectRoot) == filepath.Clean(root) {
			found = true
			if l.Editable {
				t.Error("project layer must not be editable")
			}
			if l.Overrides != 1 || len(l.Problems) != 0 {
				t.Errorf("project row = %+v, want 1 override, clean", l)
			}
		}
	}
	if !found {
		t.Errorf("project layer row missing: %+v", view.Layers)
	}
}

// TestAPIGuardPolicyOrgLayerNotes: an org bundle carrying a key this
// binary predates is LOADED (the org floor stays armed) and the
// ignored key rides the layers card as a `notes` entry — never as a
// `problems` entry, which would read as "your org policy is broken".
func TestAPIGuardPolicyOrgLayerNotes(t *testing.T) {
	t.Parallel()
	tdir := t.TempDir()
	bundlePath := filepath.Join(tdir, "org-policy-bundle.json")
	cfgPath := filepath.Join(tdir, "config.toml")
	cfgToml := "[guard]\nenabled = true\nmode = \"observe\"\n" +
		"[guard.rules]\nuser_policy = '" + filepath.ToSlash(filepath.Join(tdir, "guard-policy.toml")) + "'\n" +
		"org_bundle = '" + filepath.ToSlash(bundlePath) + "'\n"
	if err := os.WriteFile(cfgPath, []byte(cfgToml), 0o600); err != nil {
		t.Fatal(err)
	}

	const bundleTOML = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\nquarantine = true\n"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	env, err := json.Marshal(orgcontract.PolicyBundle{
		Version:    11,
		BundleTOML: bundleTOML,
		Signature:  orgcontract.SignPolicyBundle(priv, 11, []byte(bundleTOML)),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		SignedAt:   "2026-09-21T09:00:00Z",
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(bundlePath, env, 0o600); err != nil {
		t.Fatal(err)
	}

	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	s, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	rec := doGuardPolicy(t, s, "GET", "/api/guard/policy", "")
	if rec.Code != 200 {
		t.Fatalf("GET status = %d: %s", rec.Code, rec.Body.String())
	}
	var view struct {
		LoadIssues []string `json:"load_issues"`
		Layers     []struct {
			Layer    string   `json:"layer"`
			Version  string   `json:"version"`
			Notes    []string `json:"notes"`
			Problems []string `json:"problems"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	var found bool
	for _, l := range view.Layers {
		if l.Layer != "org" {
			continue
		}
		found = true
		if l.Version != "11" {
			t.Errorf("org version = %q, want 11 (the bundle was dropped?)", l.Version)
		}
		if len(l.Notes) != 1 || !strings.Contains(l.Notes[0], "override.quarantine") {
			t.Errorf("org notes = %q, want one line naming override.quarantine", l.Notes)
		}
		if len(l.Problems) != 0 {
			t.Errorf("org problems = %q, want none (a note is not a load issue)", l.Problems)
		}
	}
	if !found {
		t.Fatal("layers missing the org row")
	}
	for _, issue := range view.LoadIssues {
		if strings.Contains(issue, "org bundle") {
			t.Errorf("load issue for a loadable bundle: %q", issue)
		}
	}
}
