package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestToolGrantCountedOncePerLaunch pins review M3-10: a dashboard launch
// asks the daemon gate AND then runs the inner `observer <tool>` launcher,
// and an attached CLI launch checks before handing off to that same inner
// launcher. Only the process that starts the tool counts a use, so a
// max_uses=1 grant lets exactly one launch through, and the gates in front
// of it spend nothing.
func TestToolGrantCountedOncePerLaunch(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
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

	gate := daemonToolGrant(store.New(database))
	for i := 0; i < 3; i++ {
		if id, ok := gate("codex"); !ok || id != 9 {
			t.Fatalf("dashboard gate ask %d: id=%d ok=%v (it must not spend the grant)", i, id, ok)
		}
	}
	var errBuf bytes.Buffer
	if err := refuseIfToolDisallowedPeekCfg(cfg, "codex", &errBuf); err != nil {
		t.Fatalf("pre-attach check refused: %v %s", err, errBuf.String())
	}
	if err := refuseIfToolDisallowedCfg(cfg, "codex", &errBuf); err != nil {
		t.Fatalf("the launching process could not use the grant: %v %s", err, errBuf.String())
	}
	if _, ok := gate("codex"); ok {
		t.Fatal("the dashboard gate still allows a spent one-use grant")
	}
	if err := refuseIfToolDisallowedPeekCfg(cfg, "codex", &bytes.Buffer{}); err == nil {
		t.Fatal("the pre-attach check allows a spent one-use grant")
	}
	// A seed-only launcher (crush and its peers) now starts the tool behind
	// the same gate: a disallowed tool with no grant is refused before exec.
	if err := runSeedOnlyLaunchSeeded("", dbPath, "crush", "crush", "/bin/true", nil, ""); err == nil {
		t.Fatal("a seed-only launcher started an org-disallowed tool")
	}
}
