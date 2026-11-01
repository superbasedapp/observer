//go:build !sbo_omit_benchmark

package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestArenaCreatePreflightRefusesBeforeAnyRun (ruling P-203): a launch gate
// that refuses an Arena tool refuses the run at creation, naming the
// setting, before StartRun records a run or makes a worktree. Every
// candidate tool and the judge are asked, each once.
func TestArenaCreatePreflightRefusesBeforeAnyRun(t *testing.T) {
	var asked []string
	s := newManageServerOpts(t, Options{ArenaPreflight: func(_ context.Context, tool, root string) error {
		asked = append(asked, tool+"@"+root)
		if tool == "codex" {
			return errors.New("arena: refused by your [terminal.launch].allow_fresh_agent setting")
		}
		return nil
	}})
	h := s.Handler()
	ck, token := getConfirm(t, h)
	body := `{"run_id":"preflight-refused","project_root":"/repo","prompt":"x","candidates":[{"tool":"claude-code"},{"tool":"codex"}],"judge_tool":"claude-code"}`
	req := httptest.NewRequest(http.MethodPost, "/api/arena/runs", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(remoteConfirmHeader, token)
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "allow_fresh_agent") {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Join(asked, ",") != "claude-code@/repo,codex@/repo" {
		t.Fatalf("preflight asked %v", asked)
	}
	if run, err := s.remoteManageStore().ArenaRun(context.Background(), "preflight-refused"); err != nil || run != nil {
		t.Fatalf("a refused run was recorded: %+v err=%v", run, err)
	}
}
