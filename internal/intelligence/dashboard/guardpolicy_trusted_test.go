package dashboard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// validTrustedPolicy weakens a built-in — legal ONLY on the trusted
// per-project layer (the in-repo project layer would drop it).
const validTrustedPolicy = "[[override]]\nrule = \"R-101\"\ndecision = \"allow\"\n"

// validTrustedPolicyV2 is a distinct second version (a disable list) so
// backup-swap assertions can tell the files apart AND exercise the
// trusted-only `disable` key.
const validTrustedPolicyV2 = "disable = [\"R-152\"]\n"

// newTrustedPolicyServer builds a server whose on-disk config points the
// trusted per-project dir (and optionally a signed org bundle) INSIDE the
// test dir — these tests write real files and must never touch the
// operator's ~/.observer.
func newTrustedPolicyServer(t *testing.T, orgBundleTOML string) (srv *Server, trustedDir, tdir string) {
	t.Helper()
	tdir = t.TempDir()
	trustedDir = filepath.Join(tdir, "guard-project-policies")
	policyPath := filepath.Join(tdir, "guard-policy.toml")
	cfgPath := filepath.Join(tdir, "config.toml")

	cfgToml := "[guard]\nenabled = true\nmode = \"observe\"\n" +
		"[guard.rules]\n" +
		"user_policy = '" + filepath.ToSlash(policyPath) + "'\n" +
		"trusted_project_dir = '" + filepath.ToSlash(trustedDir) + "'\n"
	if orgBundleTOML != "" {
		orgPath := filepath.Join(tdir, "org-bundle.json")
		writeSignedBundle(t, orgPath, orgBundleTOML)
		cfgToml += "org_bundle = '" + filepath.ToSlash(orgPath) + "'\n"
	} else {
		// Pin org_bundle to a non-existent test path so LintTrustedProject
		// never reads the real ~/.observer default (no org layer here).
		cfgToml += "org_bundle = '" + filepath.ToSlash(filepath.Join(tdir, "no-org.json")) + "'\n"
	}
	if err := os.WriteFile(cfgPath, []byte(cfgToml), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	srv, err = New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	return srv, trustedDir, tdir
}

// writeSignedBundle writes a verifiable org policy-bundle envelope (the
// same shape internal/orgclient caches) to path.
func writeSignedBundle(t *testing.T, path, bundleTOML string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	b := orgcontract.PolicyBundle{
		Version:    1,
		BundleTOML: bundleTOML,
		Signature:  orgcontract.SignPolicyBundle(priv, 1, []byte(bundleTOML)),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
		SignedAt:   "2026-09-21T09:00:00Z",
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// addKnownProject upserts a project root so the trusted-write handler's
// known-root gate passes; it returns the root path.
func addKnownProject(t *testing.T, s *Server, tdir, name string) string {
	t.Helper()
	root := filepath.Join(tdir, name)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.New(s.opts.DB).UpsertProject(context.Background(), root, ""); err != nil {
		t.Fatal(err)
	}
	return root
}

func projectBody(root, content string) string {
	b, _ := json.Marshal(map[string]string{"project_root": root, "content": content})
	return string(b)
}

// TestAPIGuardProjectPolicy pins the trusted per-project write contract:
// a clean save lands atomically (weakening a built-in — impossible on the
// in-repo layer), the GET view surfaces it as an EDITABLE trusted_project
// row with content/counts, a malformed save is refused 422 (file
// untouched), and the backup swap-undo works with the trusted target.
func TestAPIGuardProjectPolicy(t *testing.T) {
	t.Parallel()
	s, _, tdir := newTrustedPolicyServer(t, "")
	root := addKnownProject(t, s, tdir, "proj")

	// Malformed save → 422; nothing lands on disk.
	rec := doGuardPolicy(t, s, "PUT", "/api/guard/policy/project",
		projectBody(root, "[[rule]]\nid = 'T-1'\nmatch.bogus = true\n"))
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

	// Clean save (a weakening override) → file on disk, counts, restart-honest.
	rec = doGuardPolicy(t, s, "PUT", "/api/guard/policy/project", projectBody(root, validTrustedPolicy))
	if rec.Code != 200 {
		t.Fatalf("PUT status = %d: %s", rec.Code, rec.Body.String())
	}
	var saveResp struct {
		Saved           bool   `json:"saved"`
		Path            string `json:"path"`
		Overrides       int    `json:"overrides"`
		RestartRequired bool   `json:"restart_required"`
		ProjectRoot     string `json:"project_root"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saveResp); err != nil {
		t.Fatalf("decode save: %v", err)
	}
	if !saveResp.Saved || saveResp.Overrides != 1 || !saveResp.RestartRequired {
		t.Errorf("save resp = %+v, want saved / 1 override / restart_required", saveResp)
	}
	if filepath.Clean(saveResp.ProjectRoot) != filepath.Clean(root) {
		t.Errorf("save project_root = %q, want %q", saveResp.ProjectRoot, root)
	}
	onDisk, err := os.ReadFile(saveResp.Path)
	if err != nil {
		t.Fatalf("read saved trusted policy: %v", err)
	}
	if string(onDisk) != validTrustedPolicy {
		t.Errorf("on-disk trusted policy drifted: %q", onDisk)
	}

	// GET view: an EDITABLE trusted_project row for this root, with content.
	rec = doGuardPolicy(t, s, "GET", "/api/guard/policy", "")
	var view struct {
		Layers []struct {
			Layer       string `json:"layer"`
			Editable    bool   `json:"editable"`
			Exists      bool   `json:"exists"`
			Content     string `json:"content"`
			Overrides   int    `json:"overrides"`
			ProjectRoot string `json:"project_root"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view: %v", err)
	}
	foundTrusted := false
	for _, l := range view.Layers {
		if l.Layer == "trusted_project" && filepath.Clean(l.ProjectRoot) == filepath.Clean(root) {
			foundTrusted = true
			if !l.Editable || !l.Exists || l.Content != validTrustedPolicy || l.Overrides != 1 {
				t.Errorf("trusted row = %+v, want editable/exists/v1 content/1 override", l)
			}
		}
	}
	if !foundTrusted {
		t.Errorf("trusted_project row missing from view: %+v", view.Layers)
	}

	// Second save keeps the prior version at .bak.
	rec = doGuardPolicy(t, s, "PUT", "/api/guard/policy/project", projectBody(root, validTrustedPolicyV2))
	if rec.Code != 200 {
		t.Fatalf("second PUT status = %d: %s", rec.Code, rec.Body.String())
	}
	bak, err := os.ReadFile(saveResp.Path + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if string(bak) != validTrustedPolicy {
		t.Errorf(".bak = %q, want the first version", bak)
	}

	// Swap-undo scoped to the trusted target via query params.
	q := "?layer=trusted_project&project_root=" + url.QueryEscape(root)
	rec = doGuardPolicy(t, s, "POST", "/api/guard/policy/backup"+q, "")
	if rec.Code != 200 {
		t.Fatalf("restore status = %d: %s", rec.Code, rec.Body.String())
	}
	onDisk, _ = os.ReadFile(saveResp.Path)
	bak, _ = os.ReadFile(saveResp.Path + ".bak")
	if string(onDisk) != validTrustedPolicy || string(bak) != validTrustedPolicyV2 {
		t.Errorf("after restore: file=%q bak=%q, want v1/v2 swapped", onDisk, bak)
	}
}

// TestAPIGuardProjectPolicyUnknownRoot pins the 409 on a root the daemon
// has never observed (no orphan trusted files).
func TestAPIGuardProjectPolicyUnknownRoot(t *testing.T) {
	t.Parallel()
	s, _, tdir := newTrustedPolicyServer(t, "")
	unknown := filepath.Join(tdir, "never-seen")

	rec := doGuardPolicy(t, s, "PUT", "/api/guard/policy/project", projectBody(unknown, validTrustedPolicy))
	if rec.Code != 409 {
		t.Fatalf("unknown-root PUT status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	// Empty root is also 409.
	rec = doGuardPolicy(t, s, "PUT", "/api/guard/policy/project", projectBody("", validTrustedPolicy))
	if rec.Code != 409 {
		t.Errorf("empty-root PUT status = %d, want 409", rec.Code)
	}
}

// TestAPIGuardProjectPolicyOrgFloor pins the security limit: a trusted
// override that would relax below the org floor is refused 422, file
// untouched.
func TestAPIGuardProjectPolicyOrgFloor(t *testing.T) {
	t.Parallel()
	// Org bundle floors R-110 at deny.
	s, _, tdir := newTrustedPolicyServer(t, "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n")
	root := addKnownProject(t, s, tdir, "proj")

	relaxing := "[[override]]\nrule = \"R-110\"\ndecision = \"allow\"\n"
	rec := doGuardPolicy(t, s, "PUT", "/api/guard/policy/project", projectBody(root, relaxing))
	if rec.Code != 422 {
		t.Fatalf("floor-relax PUT status = %d, want 422: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Saved    bool     `json:"saved"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 422: %v", err)
	}
	if resp.Saved || len(resp.Problems) == 0 {
		t.Errorf("floor-relax body = %+v, want saved=false with problems", resp)
	}

	// The lint endpoint agrees under layer=trusted_project.
	body, _ := json.Marshal(map[string]string{"content": relaxing, "layer": "trusted_project"})
	rec = doGuardPolicy(t, s, "POST", "/api/guard/policy/lint", string(body))
	var lint struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &lint); err != nil {
		t.Fatalf("decode lint: %v", err)
	}
	if lint.OK {
		t.Errorf("trusted floor-relax linted clean, want dirty")
	}
}
