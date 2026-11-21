//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// recordOwnerClaims swaps the ownership helper for a recorder that also
// performs the real claim, and returns the claimed paths.
func recordOwnerClaims(t *testing.T) *[]string {
	t.Helper()
	var claimed []string
	saved := ownSandboxRecord
	ownSandboxRecord = func(p string) error {
		claimed = append(claimed, p)
		return saved(p)
	}
	t.Cleanup(func() { ownSandboxRecord = saved })
	return &claimed
}

// TestSandboxRecordSitesCallTheOwnerHelper (Windows 11 Pro live run, B2):
// every place the sandbox creates a record folder or file on the host hands
// it to the ownership helper, so an elevated daemon or launcher never
// leaves one owned by BUILTIN\Administrators. Each row runs one create site
// and names what it must have claimed. The helper itself, and that it sets
// the owner explicitly under an elevated token, is pinned in
// internal/sandboxrelayd (TestElevatedClaimSetsTheOwnerExplicitly);
// newMXCHostRun's box folders are pinned in the Windows-only twin of this
// test.
func TestSandboxRecordSitesCallTheOwnerHelper(t *testing.T) {
	const runID = "run-own1"
	obs := t.TempDir()
	relay := filepath.Join(obs, sandboxrelayd.RelayDirName)
	cliEnd := sandboxCLIEndDir(obs)
	watch, end := sandboxCLIEndPaths(obs, runID)
	ws := t.TempDir()
	box := t.TempDir()
	// The watch stays up across rows: the end request needs its marker.
	stopWatch := func() {}
	t.Cleanup(func() { stopWatch() })

	rows := []struct {
		site string
		run  func(t *testing.T)
		want []string
	}{
		{"cli-end watch marker (watchSandboxCLIEnd)", func(t *testing.T) {
			var werr error
			_, stopWatch, werr = watchSandboxCLIEnd(obs, runID, make(chan os.Signal, 2), io.Discard)
			if werr != nil {
				t.Fatal(werr)
			}
			if _, err := os.Stat(watch); err != nil {
				t.Fatal(err)
			}
		}, []string{relay, cliEnd, watch}},
		{"cli-end end request (relayCLIRunEnder)", func(t *testing.T) {
			if !relayCLIRunEnder(obs, nil, nil)(runID, "ended", "") {
				t.Fatal("the ender wrote no request")
			}
		}, []string{end}},
		{"plan file (writeMXCPlan)", func(t *testing.T) {
			if _, err := writeMXCPlan(obs, mxcPlanFile{RunID: runID}); err != nil {
				t.Fatal(err)
			}
		}, []string{mxcStateDir(obs), filepath.Dir(mxcPlanPath(obs, runID)), mxcPlanPath(obs, runID)}},
		{"config file (writeMXCConfig)", func(t *testing.T) {
			c, err := writeMXCConfig(obs, runID, []byte("{}"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.remove)
		}, []string{filepath.Dir(mxcConfigPath(obs, runID)), mxcConfigPath(obs, runID)}},
		{"loopback record (writeMXCLoopback)", func(t *testing.T) {
			if err := writeMXCLoopback(box, mxcLoopback{V: 1, Port: 1, Token: "t"}); err != nil {
				t.Fatal(err)
			}
		}, []string{filepath.Join(box, mxcLoopbackName)}},
		{"inner log (openMXCHostLog)", func(t *testing.T) {
			l, err := openMXCHostLog(box)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(l.close)
		}, []string{mxcInnerLogPath(box)}},
		{"protected placeholders (mxcCreatePlaceholders)", func(t *testing.T) {
			if _, err := mxcCreatePlaceholders(mxcPlanFile{
				ReadWrite:        []string{ws},
				PlaceholderDirs:  []string{filepath.Join(ws, ".vscode")},
				PlaceholderFiles: []string{filepath.Join(ws, ".envrc")},
			}); err != nil {
				t.Fatal(err)
			}
		}, []string{filepath.Join(ws, ".vscode"), filepath.Join(ws, ".envrc")}},
	}
	for _, r := range rows {
		t.Run(r.site, func(t *testing.T) {
			claimed := recordOwnerClaims(t)
			r.run(t)
			if !slices.Equal(*claimed, r.want) {
				t.Fatalf("claimed %q, want %q", *claimed, r.want)
			}
		})
	}
}
