//go:build !sbo_omit_security && !sbo_omit_security_scan_trivy

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// TestIaCScheduleNeverStatsANonPathRoot (audit finding 1 on the w14
// hand-back): the IaC schedule never stats or scans the stored non-path
// "Xcode (project unknown)" root, although a folder of that name holding an
// IaC file sits in the working directory a relative stat resolves against;
// the real project is still scanned. The stat seam resolves a relative name
// against that directory, so the test process keeps its own.
func TestIaCScheduleNeverStatsANonPathRoot(t *testing.T) {
	var got []secscan.Target
	l := iacTestLoop(t, "schedule_hours = 24\n", &got)
	ctx := context.Background()
	id, err := l.st.UpsertProject(ctx, "/Users/lume/Library/Autosave Information", "")
	if err != nil {
		t.Fatal(err)
	}
	if root, _ := l.st.ProjectRootByID(ctx, id); root != xcodehost.ProjectUnknown {
		t.Fatalf("stored root = %q, want %q", root, xcodehost.ProjectUnknown)
	}
	root := iacProject(t, l)
	cwd := t.TempDir()
	planted := filepath.Join(cwd, xcodehost.ProjectUnknown)
	if err := os.MkdirAll(planted, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(planted, "main.tf"), []byte("resource \"aws_s3_bucket\" \"b\" {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var statted []string
	l.stat = func(p string) (os.FileInfo, error) {
		statted = append(statted, p)
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		return os.Stat(p)
	}
	l.pass(ctx, time.Now().Add(iacScheduleFirst+time.Minute))
	if slices.Contains(statted, xcodehost.ProjectUnknown) {
		t.Errorf("the schedule statted the non-path root: %q", statted)
	}
	for _, tg := range got {
		if tg.ProjectRoot == xcodehost.ProjectUnknown {
			t.Errorf("the schedule scanned the non-path root: %+v", got)
		}
	}
	if len(got) != 1 || got[0].ProjectRoot != root {
		t.Errorf("scheduled scans %+v, want the real project %q", got, root)
	}
}
