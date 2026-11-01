package trivy

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the driver free of its own I/O.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net", "net/http", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		Reason:    "the trivy driver does no I/O of its own; seciac.Env injects it",
	})
}

// TestRowPassesTheRegistry: the row registers, names its component, emits
// iac only and never runs on the hook path.
func TestRowPassesTheRegistry(t *testing.T) {
	t.Parallel()
	r := Row()
	if r.ID != DriverID || r.ComponentID != ComponentID || r.Kind != secscan.KindProcess {
		t.Fatalf("row %+v", r)
	}
	if _, err := secscan.NewRegistry(New(Env())); err != nil {
		t.Fatal(err)
	}
	for _, s := range r.Triggers {
		if s == policy.FindingScopePreWrite || s == policy.FindingScopeStaged {
			t.Fatalf("runs at %s", s)
		}
	}
}

// TestParseFixture: the pinned version's SARIF parses into iac findings.
func TestParseFixture(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	res, why := Parse(b, secscan.Target{ProjectRoot: "/work/project"}, "/work/project", secscan.EngineIdentity{Name: DriverID}, true, nil)
	if why != "" || len(res.Findings) == 0 || res.Findings[0].Category != policy.FindingIaC {
		t.Fatalf("%s %+v", why, res.Coverage)
	}
}

const fixture = "../../seciac/testdata/trivy-0.75.0-config.sarif"

// Env is an empty driver env for the registry test.
func Env() seciac.Env { return seciac.Env{} }
