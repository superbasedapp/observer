//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

const homeCloneURL = "https://github.com/acme/private.git"

// newHomeCloneRun is a vendor row's run of a repository this machine
// cloned (lane CLONE2, SBXD-5): the clone (two tracked files and a
// credential-shaped one) under the hosted clone root, the plan as Create
// writes it.
func newHomeCloneRun(t *testing.T, vendor string) (*hostedHarness, string) {
	t.Helper()
	hh := newHostedHarness(t, vendor)
	obs := hh.run.plan.ObserverDir
	clone := filepath.Join(hostedHomeCloneRoot(obs), "run-h1", "private")
	if err := os.MkdirAll(filepath.Join(clone, "cmd"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"go.mod": "module acme/private\n", "cmd/app.go": "package main\n", ".env.local": "TOKEN=1\n"}
	for p, body := range files {
		if err := os.WriteFile(filepath.Join(clone, filepath.FromSlash(p)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	harnessList := hostedListWorkspace
	hostedListWorkspace = func(ctx context.Context, root string) ([]sandboxremote.Candidate, bool, error) {
		if root != clone {
			return harnessList(ctx, root)
		}
		var out []sandboxremote.Candidate
		for p, body := range files {
			out = append(out, sandboxremote.Candidate{Path: p, Kind: sandboxremote.KindRegular, Size: int64(len(body))})
		}
		return out, true, nil
	}
	t.Cleanup(func() { hostedListWorkspace = harnessList })
	oldBase := hostedMeasureUploadBase
	hostedMeasureUploadBase = func(_ context.Context, root string, excluded int) hostedDiffBase {
		b := hostedDiffBase{Excluded: excluded, AgentCommits: -1, StatusKnown: true, StatusClean: true}
		if root == clone {
			b.Commit = strings.Repeat("e", 40)
		}
		return b
	}
	t.Cleanup(func() { hostedMeasureUploadBase = oldBase })
	p := &hh.run.plan
	p.Source, p.Delivery, p.CloneURL = string(workspace.SourceCloneRemote), string(workspace.DeliveryUploadSnapshot), homeCloneURL
	p.CloneWhere, p.CloneWhereReason, p.HomeCloneDir = string(workspace.CloneWhereHome), workspace.ReasonNeedsLogin, clone
	p.ScopeKey = sandboxremote.HomeCloneScopeKey(homeCloneURL)
	return hh, clone
}

// TestHostedHomeCloneVendorRun (lane CLONE2, decision SBXD-5): a clone this
// machine made reaches the box as an upload of its tracked files: no git
// runs a clone in the box, the clone's files (never the launch folder's,
// never a credential-shaped one) are uploaded, the terminal says where it
// was cloned and why and what stayed home, the temporary clone is removed
// after the upload, and the clone's commit is recorded as the diff's base.
func TestHostedHomeCloneVendorRun(t *testing.T) {
	hh, clone := newHomeCloneRun(t, sandboxremote.VendorE2B)
	hh.diff = "diff --git a/cmd/app.go b/cmd/app.go\n+// changed in the box\n"
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	if c := hostedEndRun(t, hh, code); c != 5 {
		t.Fatalf("exit %d, output %s", c, hh.out.String())
	}
	hh.mu.Lock()
	specs := append([]sandboxremote.ExecSpec(nil), hh.specs...)
	hh.mu.Unlock()
	for _, s := range specs {
		if slices.Contains(s.Argv, "clone") || slices.Contains(s.Argv, homeCloneURL) {
			t.Errorf("the box was asked to clone: %v", s.Argv)
		}
	}
	ws := hh.run.layout.Workspace
	b := hh.client.boxes["box1"]
	for _, want := range []string{"go.mod", "cmd/app.go"} {
		if _, ok := b.files[path.Join(ws, want)]; !ok {
			t.Errorf("the clone's %s was not uploaded", want)
		}
	}
	for p := range b.files {
		if strings.HasSuffix(p, ".env.local") || strings.HasSuffix(p, "main.go") {
			t.Errorf("uploaded %s (a credential-shaped file, or the launch folder's own)", p)
		}
	}
	if _, err := os.Stat(filepath.Dir(clone)); !os.IsNotExist(err) {
		t.Errorf("the temporary clone outlived the upload: %v", err)
	}
	if !b.deleted {
		t.Error("the box was not deleted")
	}
	raw, err := os.ReadFile(hostedCloneReturnPath(hh.run.plan.ObserverDir, "run-h1"))
	if err != nil {
		t.Fatal(err)
	}
	var rec hostedCloneReturn
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Commit != strings.Repeat("e", 40) || rec.CloneURL != homeCloneURL || rec.DiffAgainst != hostedCloneDiffAgainstUploadBaseline || rec.Where != "home" {
		t.Errorf("clone return record %+v", rec)
	}
	if hh.run.rec.Extra[hostedExtraCloneCommit] != "" {
		t.Error("a home clone set the box clone's commit (the box would diff against a commit it lacks)")
	}
	out := hh.out.String()
	for _, want := range []string{
		homeCloneURL + " was cloned on this machine (this repository needs a sign-in",
		"2 files", "1 excluded", "left on this machine: .env.local (credential shaped)",
		"the temporary clone at " + clone + " is removed",
		"a checkout of " + homeCloneURL + " at commit " + strings.Repeat("e", 40),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}
}

// TestHostedHomeCloneRemovedOnFailure: a run that ends before the upload
// (here, its scope does not match the consent) still removes the clone.
func TestHostedHomeCloneRemovedOnFailure(t *testing.T) {
	hh, clone := newHomeCloneRun(t, sandboxremote.VendorE2B)
	hh.run.plan.ScopeKey = sandboxremote.RemoteCloneScopeKey(homeCloneURL)
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	if c := <-code; c == 0 {
		t.Fatalf("a mismatched scope ran: %s", hh.out.String())
	}
	if strings.Contains(hh.out.String(), "uploading its tracked files") {
		t.Errorf("a mismatched scope uploaded: %s", hh.out.String())
	}
	if _, err := os.Stat(filepath.Dir(clone)); !os.IsNotExist(err) {
		t.Errorf("the clone outlived a failed run: %v", err)
	}
}
