package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestTerminalSandboxInstallVersions (lane LEFT-SBX): the version picker's
// route answers 501 with no seam, 400 for a tool outside the install-source
// catalog, the seam's versions otherwise, 502 when the registry cannot be
// read, and only GET.
func TestTerminalSandboxInstallVersions(t *testing.T) {
	s := &Server{}
	do := func(method, q string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleTerminalSandboxInstallVersions(rec, httptest.NewRequest(method, "/api/terminal/sandbox/install-versions"+q, nil))
		return rec
	}
	if rec := do(http.MethodGet, "?tool=codex"); rec.Code != http.StatusNotImplemented {
		t.Fatalf("no seam: %d", rec.Code)
	}
	s.opts = dashapi.Options{SandboxInstallVersions: func(_ context.Context, tool string) ([]string, error) {
		if tool == "gemini-cli" {
			return nil, errors.New("unreachable")
		}
		return []string{"0.164.0", "0.163.0"}, nil
	}}
	if rec := do(http.MethodGet, "?tool=codex"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"0.164.0"`) {
		t.Fatalf("codex: %d %s", rec.Code, rec.Body)
	}
	if rec := do(http.MethodGet, "?tool=not-a-tool"); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown tool: %d", rec.Code)
	}
	if rec := do(http.MethodGet, "?tool=gemini-cli"); rec.Code != http.StatusBadGateway {
		t.Fatalf("registry error: %d", rec.Code)
	}
	if rec := do(http.MethodPost, "?tool=codex"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
}
