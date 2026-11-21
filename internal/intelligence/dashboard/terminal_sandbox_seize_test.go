package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// seizeHost is a sandbox module's answer for the seam.
func seizeHost() dashapi.SandboxSeizeHost {
	return dashapi.SandboxSeizeHost{YamaScope: 0, YamaKnown: true, Rows: []dashapi.SandboxSeizeRow{
		{Backend: "bwrap", Label: "Bubblewrap", Lifted: true, Ground: "pid_namespace"},
		{Backend: "process_lite", Label: "Landlock only", Reason: "strace stays blocked (PTRACE_SEIZE denied): Yama ptrace_scope reads 0"},
	}}
}

// seizeServer is a manage server whose sandbox module answers seizeHost.
func seizeServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	s := newManageServerOpts(t, Options{SandboxSeize: seizeHost})
	return s, s.Handler()
}

// seizeGet reads the route, returning the body and the confirm cookie.
func seizeGet(t *testing.T, h http.Handler) (map[string]any, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, terminalSandboxSeizePath, nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			return out, c
		}
	}
	t.Fatal("GET minted no confirm cookie")
	return nil, nil
}

// seizePost posts body with tok and ck (either may be empty to omit it).
func seizePost(t *testing.T, h http.Handler, body, tok string, ck *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, terminalSandboxSeizePath, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set(remoteConfirmHeader, tok)
	}
	if ck != nil {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loadSeize(t *testing.T, s *Server) config.TerminalSandboxConfig {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Terminal.Sandbox
}

// TestTerminalSandboxSeizeGet: the switch is off by default, the rows are
// the sandbox module's, and a build without the module answers no rows and
// an unknown Yama.
func TestTerminalSandboxSeizeGet(t *testing.T) {
	_, h := seizeServer(t)
	out, _ := seizeGet(t, h)
	if out["enabled"] != false || out["seccomp"] != false || out["confirm_token"] == "" || out["config_writable"] != true {
		t.Fatalf("defaults: %v", out)
	}
	if out["yama_scope"] != float64(0) {
		t.Fatalf("yama_scope %v", out["yama_scope"])
	}
	rows, _ := out["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows %v", out["rows"])
	}
	bw, lite := rows[0].(map[string]any), rows[1].(map[string]any)
	if bw["backend"] != "bwrap" || bw["lifted"] != true || bw["ground"] != "pid_namespace" {
		t.Fatalf("bwrap row %v", bw)
	}
	if lite["lifted"] != false || !strings.Contains(lite["reason"].(string), "reads 0") {
		t.Fatalf("process_lite row %v", lite)
	}

	_, bare := newManageServer(t)
	out, _ = seizeGet(t, bare)
	if out["yama_scope"] != nil {
		t.Fatalf("without the module: yama_scope %v", out["yama_scope"])
	}
	if rows, ok := out["rows"].([]any); !ok || len(rows) != 0 {
		t.Fatalf("without the module: rows %v", out["rows"])
	}
}

// TestTerminalSandboxSeizePost: the confirm token is required; a confirmed
// POST writes the key and only the key; enabled is required.
func TestTerminalSandboxSeizePost(t *testing.T) {
	s, h := seizeServer(t)
	_, ck := seizeGet(t, h)
	if rec := seizePost(t, h, `{"enabled":true}`, "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := seizePost(t, h, `{"enabled":true}`, "not-the-token", ck); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if loadSeize(t, s).SeccompAllowSeize {
		t.Fatal("a refused POST wrote the key")
	}
	if rec := seizePost(t, h, `{}`, ck.Value, ck); rec.Code != http.StatusBadRequest {
		t.Fatalf("no enabled: %d", rec.Code)
	}
	rec := seizePost(t, h, `{"enabled":true}`, ck.Value, ck)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST on = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"strace"`) {
		t.Fatalf("POST answer has no strace status: %s", rec.Body.String())
	}
	got := loadSeize(t, s)
	if !got.SeccompAllowSeize || got.Seccomp || got.Enabled {
		t.Fatalf("after on: %+v", got)
	}
	if rec := seizePost(t, h, `{"enabled":false}`, ck.Value, ck); rec.Code != http.StatusOK {
		t.Fatalf("POST off = %d: %s", rec.Code, rec.Body.String())
	}
	if loadSeize(t, s).SeccompAllowSeize {
		t.Fatal("off did not save")
	}
}

// TestTerminalSandboxSeizeOnlyItsRoute: the sandbox settings save never
// writes the key (whatever its body says, and it keeps a saved on), and the
// generic config writers refuse it (owned by this route).
func TestTerminalSandboxSeizeOnlyItsRoute(t *testing.T) {
	s, h := seizeServer(t)
	body := `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,"seccomp":true,"seccomp_allow_seize":true}`
	if code, out := putSandboxConfig(t, h, body); code != http.StatusOK {
		t.Fatalf("sandbox PUT = %d: %v", code, out)
	}
	if got := loadSeize(t, s); got.SeccompAllowSeize || !got.Seccomp {
		t.Fatalf("the sandbox save wrote the strace switch: %+v", got)
	}
	_, ck := seizeGet(t, h)
	if rec := seizePost(t, h, `{"enabled":true}`, ck.Value, ck); rec.Code != http.StatusOK {
		t.Fatalf("POST on = %d: %s", rec.Code, rec.Body.String())
	}
	if code, out := putSandboxConfig(t, h, strings.Replace(body, `"seccomp_allow_seize":true`, `"seccomp_allow_seize":false`, 1)); code != http.StatusOK {
		t.Fatalf("sandbox PUT = %d: %v", code, out)
	}
	if !loadSeize(t, s).SeccompAllowSeize {
		t.Fatal("the sandbox save turned the strace switch off")
	}
	if c := configschema.CheckKey(terminalSandboxSeizeKey, nil); c.Verdict != configschema.KeyOwnerElsewhere {
		t.Fatalf("CheckKey(%s) = %v (%s), want owner_elsewhere: the keys route and config set must refuse it", terminalSandboxSeizeKey, c.Verdict, c.Message)
	}
}
