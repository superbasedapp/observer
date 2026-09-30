package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// newProfilesTestServer builds a dashboard server whose config path
// lives in a temp dir, so DefaultProfilesDir resolves to a scratch
// profiles directory.
func newProfilesTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"warn\"\n"), 0o644); err != nil {
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
	return server, cfgPath
}

func profilesReq(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(method, path, rd))
	return rr
}

// TestConfigProfilesCRUDCycle drives the full dashboard profile
// lifecycle: create from a built-in base, appear in profile_names,
// set a key, read it back resolved, delete, gone.
func TestConfigProfilesCRUDCycle(t *testing.T) {
	server, cfgPath := newProfilesTestServer(t)

	// Create, seeded from the claude-code recipe.
	rr := profilesReq(t, server, http.MethodPost, "/api/config/profiles",
		`{"name":"my-tuned","from":"claude-code"}`)
	if rr.Code != 200 {
		t.Fatalf("create: %d body=%s", rr.Code, rr.Body.String())
	}
	var created struct {
		Created      string   `json:"created"`
		ProfileNames []string `json:"profile_names"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Created != "my-tuned" || !slices.Contains(created.ProfileNames, "my-tuned") {
		t.Fatalf("create response: %+v", created)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cfgPath), "profiles", "my-tuned.toml")); err != nil {
		t.Fatalf("profile file not written: %v", err)
	}

	// Set a key (the CLI `profile set` equivalent).
	rr = profilesReq(t, server, http.MethodPatch, "/api/config/profiles/my-tuned",
		`{"key":"compression.conversation.target_ratio","value":"0.7"}`)
	if rr.Code != 200 {
		t.Fatalf("patch: %d body=%s", rr.Code, rr.Body.String())
	}

	// GET shows the resolved value + raw body, marked editable.
	rr = profilesReq(t, server, http.MethodGet, "/api/config/profiles/my-tuned", "")
	if rr.Code != 200 {
		t.Fatalf("get: %d body=%s", rr.Code, rr.Body.String())
	}
	var shown struct {
		Name     string `json:"name"`
		Builtin  bool   `json:"builtin"`
		Editable bool   `json:"editable"`
		Raw      string `json:"raw"`
		Resolved struct {
			Conversation struct {
				TargetRatio float64 `json:"TargetRatio"`
			} `json:"Conversation"`
		} `json:"resolved"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&shown); err != nil {
		t.Fatal(err)
	}
	if shown.Builtin || !shown.Editable {
		t.Errorf("flags: builtin=%v editable=%v", shown.Builtin, shown.Editable)
	}
	if shown.Resolved.Conversation.TargetRatio != 0.7 {
		t.Errorf("resolved target_ratio: got %v want 0.7", shown.Resolved.Conversation.TargetRatio)
	}
	if !strings.Contains(shown.Raw, "target_ratio") {
		t.Errorf("raw body missing set key:\n%s", shown.Raw)
	}

	// Delete; name leaves the set.
	rr = profilesReq(t, server, http.MethodDelete, "/api/config/profiles/my-tuned", "")
	if rr.Code != 200 {
		t.Fatalf("delete: %d body=%s", rr.Code, rr.Body.String())
	}
	var deleted struct {
		ProfileNames []string `json:"profile_names"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&deleted); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(deleted.ProfileNames, "my-tuned") {
		t.Errorf("profile still listed after delete: %v", deleted.ProfileNames)
	}
}

// TestConfigProfilesGuards pins the refusal matrix: built-ins are
// immutable and undeletable, duplicate creates 409, bad names 400,
// unknown profiles 404, GET on a built-in works read-only.
func TestConfigProfilesGuards(t *testing.T) {
	server, _ := newProfilesTestServer(t)

	cases := []struct {
		label  string
		method string
		path   string
		body   string
		want   int
	}{
		{"create reserved name", http.MethodPost, "/api/config/profiles", `{"name":"claude-code"}`, 400},
		{"create invalid name", http.MethodPost, "/api/config/profiles", `{"name":"Bad Name!"}`, 400},
		{"patch builtin", http.MethodPatch, "/api/config/profiles/claude-code", `{"key":"compression.conversation.target_ratio","value":"0.5"}`, 400},
		{"delete builtin", http.MethodDelete, "/api/config/profiles/claude-code", "", 400},
		{"patch unknown", http.MethodPatch, "/api/config/profiles/nope", `{"key":"compression.conversation.target_ratio","value":"0.5"}`, 404},
		{"delete unknown", http.MethodDelete, "/api/config/profiles/nope", "", 404},
		{"get unknown", http.MethodGet, "/api/config/profiles/nope", "", 404},
		{"create method guard", http.MethodGet, "/api/config/profiles", "", 405},
	}
	for _, tc := range cases {
		rr := profilesReq(t, server, tc.method, tc.path, tc.body)
		if rr.Code != tc.want {
			t.Errorf("%s: got %d want %d (body=%s)", tc.label, rr.Code, tc.want, rr.Body.String())
		}
	}

	// Duplicate create → 409.
	if rr := profilesReq(t, server, http.MethodPost, "/api/config/profiles", `{"name":"dup"}`); rr.Code != 200 {
		t.Fatalf("seed create: %d", rr.Code)
	}
	if rr := profilesReq(t, server, http.MethodPost, "/api/config/profiles", `{"name":"dup"}`); rr.Code != 409 {
		t.Errorf("duplicate create: got %d want 409", rr.Code)
	}

	// Built-in GET is read-only but works (the reference card's data).
	rr := profilesReq(t, server, http.MethodGet, "/api/config/profiles/codex-safe", "")
	if rr.Code != 200 {
		t.Fatalf("get builtin: %d body=%s", rr.Code, rr.Body.String())
	}
	var shown struct {
		Builtin  bool   `json:"builtin"`
		Editable bool   `json:"editable"`
		Raw      string `json:"raw"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&shown); err != nil {
		t.Fatal(err)
	}
	if !shown.Builtin || shown.Editable || !strings.Contains(shown.Raw, "[compression") {
		t.Errorf("builtin GET shape: builtin=%v editable=%v rawLen=%d", shown.Builtin, shown.Editable, len(shown.Raw))
	}

	// PATCH refuses non-compression keys (the SetKey allow-list).
	if rr := profilesReq(t, server, http.MethodPatch, "/api/config/profiles/dup",
		`{"key":"observer.db_path","value":"/tmp/evil.db"}`); rr.Code != 400 {
		t.Errorf("non-compression key: got %d want 400", rr.Code)
	}
}
