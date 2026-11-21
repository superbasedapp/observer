package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
)

// Sweep findings UI-3 and UI-7a against the recipe surfaces: the heavy
// simulate GET runs one at a time, stops when its request goes away and
// refuses a cross-site browser request; a user recipe's raw file and the
// preview's absolute paths stay on this machine.

// TestGuardSimulate_RefusesCrossSite: a page on another site can make a
// browser send a GET with no Origin and no Referer (an <img>), which the
// loopback guard lets through; Sec-Fetch-Site still names it.
func TestGuardSimulate_RefusesCrossSite(t *testing.T) {
	s, _, _ := newGuardRecipeServer(t)
	for _, tc := range []struct {
		site string
		want int
	}{
		{"cross-site", http.StatusForbidden},
		{"same-origin", http.StatusOK},
		{"", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/guard/simulate?hours=24", nil)
		if tc.site != "" {
			req.Header.Set("Sec-Fetch-Site", tc.site)
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("Sec-Fetch-Site %q: %d, want %d (%s)", tc.site, rr.Code, tc.want, rr.Body.String())
		}
	}
}

// TestGuardSimulate_OneAtATime: while one simulation runs, a second waits
// for it and gives up when its own request goes away, evaluating nothing.
func TestGuardSimulate_OneAtATime(t *testing.T) {
	s, _, _ := newGuardRecipeServer(t)
	release, err := acquireGuardSimulateSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/guard/simulate?hours=24", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	start := time.Now()
	s.handleGuardSimulate(rr, req)
	if rr.Code != http.StatusServiceUnavailable || strings.Contains(rr.Body.String(), "scanned") {
		t.Fatalf("a second simulation while one runs: %d %s", rr.Code, rr.Body.String())
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the waiting simulation did not give up with its request")
	}
	release()
	rr = httptest.NewRecorder()
	s.handleGuardSimulate(rr, httptest.NewRequest(http.MethodGet, "/api/guard/simulate?hours=24", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("after the slot is free: %d %s", rr.Code, rr.Body.String())
	}
}

// TestGuardSimulate_StopsWhenTheRequestGoes: the evaluation checks the
// request's context between chunks, so a closed request stops the replay.
func TestGuardSimulate_StopsWhenTheRequestGoes(t *testing.T) {
	inputs := make([]guard.ActionInput, 10)
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := evaluateCancellable(ctx, inputs, 3, func(chunk []guard.ActionInput) []guard.ActionVerdict {
		calls++
		if calls == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatalf("calls %d, err %v: want 2 chunks then context.Canceled", calls, err)
	}
	got := 0
	out, err := evaluateCancellable(context.Background(), inputs, 3, func(chunk []guard.ActionInput) []guard.ActionVerdict {
		got += len(chunk)
		return make([]guard.ActionVerdict, len(chunk))
	})
	if err != nil || got != 10 || len(out) != 10 {
		t.Fatalf("a full run evaluates every input once in order: %d %d %v", got, len(out), err)
	}
	// A cancelled request evaluates nothing at all.
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	s, _, _ := newGuardRecipeServer(t)
	rr := httptest.NewRecorder()
	s.handleGuardSimulate(rr, httptest.NewRequest(http.MethodGet, "/api/guard/simulate?hours=24&recipe=1&level=lockdown", nil).WithContext(cancelled))
	if rr.Code == http.StatusOK {
		t.Fatalf("a cancelled simulation answered 200: %s", rr.Body.String())
	}
}

// TestGuardRecipeShow_UserRecipeIsLocal: a user recipe's raw file (its
// comments, its notes) is shown on this machine only; a built-in recipe,
// which every install carries, stays a View read.
func TestGuardRecipeShow_UserRecipeIsLocal(t *testing.T) {
	s, _, _ := newGuardRecipeServer(t)
	mine := "# my notes: prod is db7.internal\nname = \"mine\"\nkind = \"pack\"\ntitle = \"Mine\"\nsummary = \"My pack.\"\nversion = 1\n\n[[override]]\nrule = \"R-140\"\ndecision = \"deny\"\n"
	body, _ := json.Marshal(map[string]string{"name": "mine", "toml": mine})
	if rr := postGuardRecipe(t, s, "/api/guard/recipes/user", string(body), true); rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	show := func(name string, remote bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/guard/recipes/show?name="+name, nil)
		if remote {
			req = req.WithContext(withRemoteExposed(req.Context()))
		}
		rr := httptest.NewRecorder()
		s.handleGuardRecipeShow(rr, req)
		return rr
	}
	if rr := show("mine", true); rr.Code != http.StatusForbidden || strings.Contains(rr.Body.String(), "db7.internal") {
		t.Fatalf("a remote show of a user recipe: %d %s", rr.Code, rr.Body.String())
	}
	if rr := show("mine", false); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "db7.internal") {
		t.Fatalf("a local show of a user recipe: %d %s", rr.Code, rr.Body.String())
	}
	if rr := show("strict", true); rr.Code != http.StatusOK {
		t.Fatalf("a remote show of a built-in recipe: %d %s", rr.Code, rr.Body.String())
	}
}

// TestGuardRecipePreview_RemoteHasNoPaths: a remote viewer's preview keeps
// what changes and drops the file the apply writes and the absolute paths.
func TestGuardRecipePreview_RemoteHasNoPaths(t *testing.T) {
	s, _, dir := newGuardRecipeServer(t)
	preview := func(remote bool) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/guard/recipes/preview?level=strict&scope=global", nil)
		if remote {
			req = req.WithContext(withRemoteExposed(req.Context()))
		}
		rr := httptest.NewRecorder()
		s.handleGuardRecipePreview(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("preview (remote %v): %d %s", remote, rr.Code, rr.Body.String())
		}
		var v map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	local := preview(false)
	if p, _ := local["path"].(string); p == "" || local["text"] == nil {
		t.Fatalf("a local preview carries the path and the file: %v", local)
	}
	remote := preview(true)
	if p, _ := remote["path"].(string); p != "" {
		t.Fatalf("a remote preview carries the path %q", p)
	}
	if txt, _ := remote["text"].(string); txt != "" {
		t.Fatal("a remote preview carries the compiled file")
	}
	if remote["changes"] == nil || remote["mode_after"] != "enforce" {
		t.Fatalf("a remote preview still says what changes: %v", remote)
	}
	raw, _ := json.Marshal(remote)
	jsonDir := strings.ReplaceAll(dir, `\`, `\\`) // the directory as JSON spells it
	if strings.Contains(string(raw), jsonDir) || strings.Contains(string(raw), filepath.ToSlash(dir)) {
		t.Fatalf("a remote preview names the policy directory: %s", raw)
	}
}
