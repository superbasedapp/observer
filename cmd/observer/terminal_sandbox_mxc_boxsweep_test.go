//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMXCBoxSweepRemovesOnlyItsOwnStaleFolders (RERUN2 D4): the sweep
// removes a box folder of this Observer home whose run is gone, and keeps a
// live run's folder, a folder with no owner file (named like a box folder,
// never recognised by name alone), another home's folder, a folder whose
// owner file names another run, and an unrelated folder. Before, nothing
// removed a box folder its helper left behind.
func TestMXCBoxSweepRemovesOnlyItsOwnStaleFolders(t *testing.T) {
	tmp := t.TempDir()
	obs := filepath.Join(t.TempDir(), ".observer")
	other := filepath.Join(t.TempDir(), ".observer")
	mk := func(name string) string {
		d := filepath.Join(tmp, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		return d
	}
	stale := mk(mxcBoxDirPrefix + "run-stale")
	if err := writeMXCBoxOwner(stale, "run-stale", obs); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stale, "tmp", "claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	live := mk(mxcBoxDirPrefix + "run-live")
	_ = writeMXCBoxOwner(live, "run-live", obs)
	byName := mk(mxcBoxDirPrefix + "run-noowner")
	foreign := mk(mxcBoxDirPrefix + "run-foreign")
	_ = writeMXCBoxOwner(foreign, "run-foreign", other)
	mismatch := mk(mxcBoxDirPrefix + "run-a")
	_ = writeMXCBoxOwner(mismatch, "run-b", obs)
	unrelated := mk("something-else")
	isLive := func(id string) bool { return id == "run-live" }

	removed, err := mxcSweepStaleBoxDirs(tmp, obs, isLive)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != stale {
		t.Fatalf("removed %v, want only %s", removed, stale)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("the stale folder is still there: %v", err)
	}
	for _, d := range []string{live, byName, foreign, mismatch, unrelated} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("%s was removed: %v", d, err)
		}
	}
	for d, want := range map[string]mxcBoxSweepVerdict{
		live: mxcSweepLive, byName: mxcSweepNotABox, foreign: mxcSweepOtherHome, mismatch: mxcSweepNameNoMatch,
	} {
		if got := mxcJudgeBoxDir(d, obs, isLive); got != want {
			t.Errorf("%s: %q, want %q", filepath.Base(d), got, want)
		}
	}
}
