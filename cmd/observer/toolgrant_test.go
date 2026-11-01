//go:build !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestBareLauncherHonoursAToolGrant (request-grants G8): a bare CLI launch
// of an org-disallowed tool proceeds under a verified tool access grant for
// exactly that tool, counting one use per launch and saying so; without a
// grant (or once its uses are spent) it is refused with the request path,
// never "contact your administrator".
func TestBareLauncherHonoursAToolGrant(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Now()
	seedVerifiedGrant(t, store.New(database), orgcontract.AccessGrantWire{
		ID: 9, Type: accessgrant.TypeToolAllow, Target: "codex", SubjectKind: orgcontract.AccessGrantSubjectMember,
		StartsAtNs: now.Add(-time.Minute).UnixNano(), ExpiresAtNs: now.Add(time.Hour).UnixNano(), MaxUses: 1,
	})
	var cfg config.Config
	cfg.Observer.DBPath = dbPath
	makeFeaturesSidecarWriter(cfg, "v-test", nil)([]string{"codex", "crush"}, nil)

	var errBuf bytes.Buffer
	if err := refuseIfToolDisallowedCfg(cfg, "codex", &errBuf); err != nil {
		t.Fatalf("granted launch refused: %v (%s)", err, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "org grant #9") {
		t.Fatalf("the launch does not say it runs under the grant: %q", errBuf.String())
	}
	errBuf.Reset()
	if err := refuseIfToolDisallowedDB(dbPath, "codex", &errBuf); err == nil {
		t.Fatal("a one-use grant allowed a second launch")
	}
	for _, want := range []string{"disallowed this tool", "observer request tool codex"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("refusal %q missing %q", errBuf.String(), want)
		}
	}
	if strings.Contains(errBuf.String(), "Contact your administrator") {
		t.Errorf("refusal still says contact your administrator: %q", errBuf.String())
	}
	if err := refuseIfToolDisallowedCfg(cfg, "crush", &bytes.Buffer{}); err == nil {
		t.Fatal("a grant for codex let crush launch")
	}
	// An allowed tool never asks for (or spends) a grant.
	if err := refuseIfToolDisallowedCfg(cfg, "claude-code", &bytes.Buffer{}); err != nil {
		t.Fatalf("allowed tool refused: %v", err)
	}
}

// TestDashboardLaunchHonoursAToolGrant: the dashboard's fresh launch asks
// the same grant question through the daemon's handle, only when the org
// disallows the tool, and its refusal names the request path.
func TestDashboardLaunchHonoursAToolGrant(t *testing.T) {
	nf := newNodeFeaturesHandle()
	nf.recordApplied(3, "bh", nodefeatures.PolicySpec{Tools: nodefeatures.ToolsRule{Governed: true, Disallow: map[string]bool{"codex": true}}})
	var asked []string
	grants := map[string]int64{"codex": 12}
	nf.SetToolGrant(func(tool string) (int64, bool) {
		asked = append(asked, tool)
		id, ok := grants[tool]
		delete(grants, tool)
		return id, ok
	})
	if ok, why, id := nf.ToolLaunchAllowed("codex"); !ok || id != 12 || !strings.Contains(why, "#12") {
		t.Fatalf("granted: ok=%v why=%q id=%d", ok, why, id)
	}
	if ok, _, _ := nf.ToolLaunchAllowed("codex"); ok {
		t.Fatal("a spent grant allowed a second launch")
	}
	if ok, _, _ := nf.ToolLaunchAllowed("claude-code"); !ok {
		t.Fatal("an allowed tool was refused")
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v: an allowed tool must not consult grants", asked)
	}
	a := &launchManagerAdapter{nf: nf}
	_, err := a.CreateFresh(dashapi.FreshLaunchSpec{Tool: "codex"})
	if !errors.Is(err, dashapi.ErrLaunchToolNotAllowed) || !strings.Contains(err.Error(), "request access") {
		t.Fatalf("refusal %v", err)
	}
}
