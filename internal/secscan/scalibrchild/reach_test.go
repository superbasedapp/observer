//go:build !sbo_omit_security_scan_scalibr

package scalibrchild

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachgo"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

const reachRec = `{"id":"GO-2099-0001","aliases":["GHSA-aaaa-bbbb-cccc"],"affected":[{"package":{"ecosystem":"Go","name":"example.com/lib"},
"ecosystem_specific":{"imports":[{"path":"example.com/lib/jwt","symbols":["Claims.VerifyAudience"]}]}}]}`

const reachRec2 = `{"id":"GO-2099-0002","affected":[{"package":{"ecosystem":"Go","name":"example.com/lib"},
"ecosystem_specific":{"imports":[{"path":"example.com/lib/text","symbols":["MatchStrings"]}]}}]}`

// reachResp is a scanned Go ecosystem with two advisories on a binary's
// package and one on a go.mod package (never checked: not an artifact).
func reachResp(bins ...string) depscan.ChildResponse {
	resp := depscan.ChildResponse{}
	eco := depscan.EcoResult{Ecosystem: "Go", Outcome: depscan.EcoScanned}
	for _, b := range bins {
		resp.Packages = append(resp.Packages, depscan.Package{Ecosystem: "Go", Name: "example.com/lib", Version: "1.0.0", Path: b, Artifact: true})
		i := len(resp.Packages) - 1
		eco.Advisories = append(eco.Advisories,
			depscan.Advisory{ID: "GO-2099-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Index: i},
			depscan.Advisory{ID: "GO-2099-0002", Index: i})
	}
	resp.Packages = append(resp.Packages, depscan.Package{Ecosystem: "Go", Name: "example.com/lib", Version: "1.0.0", Path: "go.mod"})
	eco.Advisories = append(eco.Advisories, depscan.Advisory{ID: "GO-2099-0001", Index: len(resp.Packages) - 1})
	resp.Ecosystems = []depscan.EcoResult{eco}
	return resp
}

func reachReq(t *testing.T, bins ...string) depscan.ChildRequest {
	t.Helper()
	root, db := t.TempDir(), t.TempDir()
	writeDB(t, db, "Go", map[string]string{"GO-2099-0001.json": reachRec, "GO-2099-0002.json": reachRec2})
	for _, b := range bins {
		p := filepath.Join(root, filepath.FromSlash(b))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("\x7fELF fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return depscan.ChildRequest{Root: root, DBDir: db, ScratchDir: t.TempDir(), ReachGo: true}
}

const fakeStream = `{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/lib","version":"v1.0.0"}]}}
{"finding":{"osv":"GO-2099-0001","trace":[{"module":"example.com/lib","package":"example.com/lib/jwt","function":"VerifyAudience","receiver":"Claims"}]}}
{"finding":{"osv":"GO-2099-0002","trace":[{"module":"example.com/lib","package":"example.com/lib/text"}]}}
{"finding":{"osv":"GHSA-aaaa-bbbb-cccc","trace":[{"module":"example.com/lib","package":"example.com/lib/jwt","function":"Sign"}]}}
`

func swapReach(t *testing.T, checkable bool, run func(ctx context.Context, db, bin string, out, errOut io.Writer) error) {
	t.Helper()
	oldR, oldI := reachRunner, reachInspect
	t.Cleanup(func() { reachRunner, reachInspect = oldR, oldI })
	reachRunner = run
	reachInspect = func(io.ReaderAt) secreachgo.Inspection {
		if checkable {
			return secreachgo.Inspection{Format: secreachgo.FormatELF, Checkable: true}
		}
		return secreachgo.Inspection{Format: secreachgo.FormatELF, Reason: secreach.ReasonStripped}
	}
}

func TestReachGoDecidesEachBinary(t *testing.T) {
	var dbSeen []string
	swapReach(t, true, func(_ context.Context, db, bin string, out, _ io.Writer) error {
		entries, _ := os.ReadDir(db)
		for _, e := range entries {
			dbSeen = append(dbSeen, e.Name())
		}
		if !filepath.IsAbs(bin) || !strings.HasSuffix(filepath.ToSlash(bin), "bin/app") {
			t.Errorf("binary %q", bin)
		}
		_, err := io.WriteString(out, fakeStream)
		return err
	})
	req := reachReq(t, "bin/app")
	runs := reachGo(context.Background(), req, reachResp("bin/app"))
	if len(runs) != 1 || runs[0].Target != "bin/app" || runs[0].Source != secreach.SourceGovulncheckBinary || runs[0].Reason != "" {
		t.Fatalf("runs: %+v", runs)
	}
	got := map[string]secreach.SymbolVerdict{}
	for _, r := range runs[0].Records {
		got[r.ID] = r.Verdict
	}
	want := map[string]secreach.SymbolVerdict{"GO-2099-0001": secreach.VerdictCalled, "GHSA-aaaa-bbbb-cccc": secreach.VerdictCalled, "GO-2099-0002": secreach.VerdictNotCalled}
	for id, v := range want {
		if got[id] != v {
			t.Errorf("%s = %q, want %q (all: %v)", id, got[id], v, got)
		}
	}
	if strings.Join(dbSeen, ",") != "GO-2099-0001.json,GO-2099-0002.json" {
		t.Errorf("flat database %v", dbSeen)
	}
	// The flat database is removed after the run.
	if left, _ := os.ReadDir(req.ScratchDir); len(left) != 0 {
		t.Errorf("scratch left: %v", left)
	}
}

func TestReachGoNeverRunsAStrippedBinary(t *testing.T) {
	swapReach(t, false, func(context.Context, string, string, io.Writer, io.Writer) error {
		t.Error("govulncheck ran over a stripped binary")
		return nil
	})
	runs := reachGo(context.Background(), reachReq(t, "bin/app"), reachResp("bin/app"))
	if len(runs) != 1 || runs[0].Reason != secreach.ReasonStripped || len(runs[0].Records) != 0 {
		t.Fatalf("runs: %+v", runs)
	}
}

func TestReachGoFailuresAreUnknown(t *testing.T) {
	cases := []struct {
		name string
		run  func(ctx context.Context, db, bin string, out, errOut io.Writer) error
		want secreach.Reason
	}{
		{"engine error", func(context.Context, string, string, io.Writer, io.Writer) error { return errors.New("boom") }, secreach.ReasonSymbolCheckFailed},
		{"bad stream", func(_ context.Context, _, _ string, out, _ io.Writer) error {
			_, err := io.WriteString(out, `{"finding":`)
			return err
		}, secreach.ReasonSymbolCheckFailed},
		{"timeout", func(ctx context.Context, _, _ string, _, _ io.Writer) error { <-ctx.Done(); return ctx.Err() }, secreach.ReasonTimedOut},
	}
	old := reachTimeout
	t.Cleanup(func() { reachTimeout = old })
	reachTimeout = 50 * time.Millisecond
	for _, tc := range cases {
		swapReach(t, true, tc.run)
		runs := reachGo(context.Background(), reachReq(t, "bin/app"), reachResp("bin/app"))
		if len(runs) != 1 || runs[0].Reason != tc.want {
			t.Errorf("%s: %+v, want %q", tc.name, runs, tc.want)
		}
	}
}

func TestReachGoCapsAndScope(t *testing.T) {
	ran := 0
	swapReach(t, true, func(_ context.Context, _, _ string, out, _ io.Writer) error {
		ran++
		_, err := io.WriteString(out, fakeStream)
		return err
	})
	var bins []string
	for i := 0; i < MaxReachBinaries+2; i++ {
		bins = append(bins, "dist/b"+string(rune('a'+i)))
	}
	runs := reachGo(context.Background(), reachReq(t, bins...), reachResp(bins...))
	if len(runs) != len(bins) || ran != MaxReachBinaries {
		t.Fatalf("%d runs, %d checked", len(runs), ran)
	}
	for _, r := range runs[MaxReachBinaries:] {
		if r.Reason != secreach.ReasonBinaryCap {
			t.Errorf("past the cap: %+v", r)
		}
	}
	// Nothing to check: no Go binary, a Go ecosystem not scanned.
	if runs := reachGo(context.Background(), reachReq(t), reachResp()); runs != nil {
		t.Fatalf("no binary: %+v", runs)
	}
	resp := reachResp("bin/app")
	resp.Ecosystems[0].Outcome = depscan.EcoNotScanned
	if runs := reachGo(context.Background(), reachReq(t, "bin/app"), resp); runs != nil {
		t.Fatalf("not scanned: %+v", runs)
	}
	// No database: every binary unknown, nothing run.
	req := reachReq(t, "bin/app")
	req.DBDir = filepath.Join(req.DBDir, "missing")
	ran = 0
	runs = reachGo(context.Background(), req, reachResp("bin/app"))
	if len(runs) != 1 || runs[0].Reason != secreach.ReasonSymbolCheckFailed || ran != 0 {
		t.Fatalf("no database: %+v (ran %d)", runs, ran)
	}
}
