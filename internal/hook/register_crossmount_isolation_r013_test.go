package hook

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// R-013 (incident 2026-10-25, decision log P-152): a real `observer init` in
// WSL with HOME set to a temp dir rewrote the operator's real Windows Claude
// Code settings through crossmount detection. This is the same fixture as
// PT-06 but with discovery ALLOWED and the account's real home pinned
// (ForeignLayoutForTest.RealHome), so the production isolation rule, not the
// test-binary guard, is what must keep the writers out of the foreign home.
// The control pins HOME at the real home and shows the Windows bridge is
// still registered there. Not parallel: it sets HOME and stages process-wide
// crossmount state.
func TestR013IsolatedHomeRegistersNothingInTheForeignHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the -windows bridge targets only exist for a Linux (WSL) daemon")
	}
	stage := func(t *testing.T, realHome func(f pt06Fixture) string) pt06Fixture {
		f := newPT06Fixture(t, true)
		crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{
			Root: f.usersRoot, WindowsUser: "operator", Discover: true, RealHome: realHome(f),
		})
		return f
	}

	t.Run("HOME outside the real home: the foreign home is untouched", func(t *testing.T) {
		realHome := t.TempDir()
		f := stage(t, func(pt06Fixture) string { return realHome })
		before := treeDigest(t, f.winHome)
		results := pt06Register(t)
		after := treeDigest(t, f.winHome)
		for p, sum := range after {
			if before[p] != sum {
				t.Errorf("registration under an isolated HOME wrote %s in the foreign home", p)
			}
		}
		for p := range before {
			if _, ok := after[p]; !ok {
				t.Errorf("registration under an isolated HOME removed %s from the foreign home", p)
			}
		}
		for target, res := range results {
			if strings.HasSuffix(target, "-windows") && len(res.HooksAdded) > 0 {
				t.Errorf("%s added %v under an isolated HOME", target, res.HooksAdded)
			}
		}
	})

	t.Run("control: HOME is the real home, the Windows bridge registers", func(t *testing.T) {
		f := stage(t, func(f pt06Fixture) string { return f.home })
		res := pt06Register(t)["claude-code-windows"]
		if res.Error != nil || !crossmount.PathUnder(f.winHome, res.ConfigPath) {
			t.Fatalf("claude-code-windows: config %q, error %v; the real-home case must still register the bridge", res.ConfigPath, res.Error)
		}
		b, err := os.ReadFile(filepath.Join(f.winHome, ".claude", "settings.json"))
		if err != nil || !strings.Contains(string(b), "wsl.exe -d TestDistro") {
			t.Errorf("the Windows settings lack the wsl.exe bridge (%v)", err)
		}
	})
}
