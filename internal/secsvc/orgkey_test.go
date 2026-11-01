//go:build !sbo_omit_security

package secsvc

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestHistoryFindingCarriesOrgKey (lane LEFT-SHARED merge audit finding 5):
// with the org dedupe key held, a secret the history scan finds carries the
// same version-tagged org_key the daemon's detector notes for that secret;
// without the key it carries none.
func TestHistoryFindingCarriesOrgKey(t *testing.T) {
	ctx := context.Background()
	secret := "ghp_" + strings.Repeat("a1B2", 9)
	text := "token = \"" + secret + "\"\n"
	for _, held := range []bool{true, false} {
		dir, run := gitRepo(t)
		writeFile(t, dir, "conf.py", text)
		run("add", "-A")
		run("commit", "-q", "-m", "add a token")
		cfg := filepath.Join(t.TempDir(), "config.toml")
		secDir := secposture.LayoutFor(cfg).Dir
		if err := os.MkdirAll(secDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if held {
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, orgcontract.SecurityOrgDedupeKeyBytes))
			if err := WriteOrgDedupeKey(secDir, &orgcontract.SecurityOrgDedupe{Version: 5, Key: key}); err != nil {
				t.Fatal(err)
			}
		}
		st := realStore(t)
		res, err := ScanHistory(ctx, LocalHistoryDeps(cfg, "test-pack", st), dir, HistoryOptions{})
		if err != nil || res.Hits != 1 {
			t.Fatalf("held=%v: history %+v %v", held, res, err)
		}
		fs, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(dir)})
		if err != nil || len(fs) != 1 {
			t.Fatalf("held=%v: findings %+v %v", held, fs, err)
		}
		// The daemon's detector path over the same text, same node key.
		memo := &OrgKeyMemo{}
		identify, err := SecretIdentify(secDir, memo)
		if err != nil {
			t.Fatal(err)
		}
		r := secdetect.Scanner{Identify: identify}.Scan(text, "conf.py", secdetect.HookLimits)
		if len(r.Hits) != 1 {
			t.Fatalf("detector hits: %+v", r.Hits)
		}
		want := memo.For(r.Hits[0].Identity)
		if held && (want == "" || !strings.HasPrefix(want, "v5:") || fs[0].OrgKey != want) {
			t.Fatalf("history org_key %q, the detector's %q", fs[0].OrgKey, want)
		}
		if !held && (fs[0].OrgKey != "" || want != "") {
			t.Fatalf("no key held, yet org_key %q / %q", fs[0].OrgKey, want)
		}
	}
}

// TestOrgDedupeKeyFile: the key file is owner-only, a malformed key writes
// nothing, nil removes the file, and OrgDedupeFor follows the applied pull.
func TestOrgDedupeKeyFile(t *testing.T) {
	dir := t.TempDir()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, orgcontract.SecurityOrgDedupeKeyBytes))
	d := &orgcontract.SecurityOrgDedupe{Version: 2, Key: key}
	if err := WriteOrgDedupeKey(dir, d); err != nil {
		t.Fatal(err)
	}
	if got, ok := ReadOrgDedupe(dir); !ok || got != *d {
		t.Fatalf("read back %+v %v", got, ok)
	}
	if err := WriteOrgDedupeKey(dir, &orgcontract.SecurityOrgDedupe{Version: 3, Key: "short"}); err == nil {
		t.Fatal("a malformed key must be refused")
	}
	if got, _ := ReadOrgDedupe(dir); got.Version != 2 {
		t.Fatalf("a refused key changed the file: %+v", got)
	}
	if err := WriteOrgDedupeKey(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadOrgDedupe(dir); ok {
		t.Fatal("nil must remove the key file")
	}
	p := &orgcontract.SecurityManagedPolicyV1{Version: 1, OrgDedupe: d}
	if OrgDedupeFor(true, p) != d || OrgDedupeFor(false, p) != nil || OrgDedupeFor(true, nil) != nil {
		t.Fatal("OrgDedupeFor follows the in-force pull only")
	}
}
