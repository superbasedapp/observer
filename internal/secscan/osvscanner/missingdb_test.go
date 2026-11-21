package osvscanner

import (
	"context"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// unoffered is an ecosystem osv-scanner reads that Observer downloads no
// database for.
const unoffered = "opam"

func TestMissingDatabaseLine(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"could not find local databases for ecosystems: Pub, Hex", []string{"Pub", "Hex"}},
		{"Could not find local database for ecosystem: SwiftURL", []string{"SwiftURL"}},
		{"could not find local databases for ecosystems: ", nil},
		{"could not extract from " + root + "/pubspec.lock: x", nil},
		{"Error: something went wrong", nil},
	}
	for _, c := range cases {
		got, ok := missingDatabaseEcosystems(c.line)
		if ok != (c.want != nil) || !slices.Equal(got, c.want) {
			t.Errorf("%q: %v %v, want %v", c.line, got, ok, c.want)
		}
	}
}

// TestMissingDatabaseIsNoExtractionFailure: a line naming only ecosystems
// Observer offers no database for fails no ecosystem (they become gaps);
// one naming an ecosystem Observer does offer cannot be placed and fails
// every ecosystem.
func TestMissingDatabaseIsNoExtractionFailure(t *testing.T) {
	if depscan.OSVScannerReads(unoffered) {
		t.Fatalf("%s is offered now; pick an ecosystem Observer has no database for", unoffered)
	}
	f := readStderr([]byte("could not find local databases for ecosystems: "+unoffered+"\n"), false, root, canary)
	if len(f.failures()) != 0 || !slices.Equal(f.missing, []string{unoffered}) {
		t.Fatalf("failures %+v missing %v", f.failures(), f.missing)
	}
	f = readStderr([]byte("could not find local databases for ecosystems: npm, "+unoffered+"\n"), false, root, canary)
	if got := f.failures(); len(got) != len(depscan.OSVScannerEcosystems()) {
		t.Fatalf("failures %+v: a missing database Observer offers fails every ecosystem", got)
	}
}

func TestMissingDatabaseGaps(t *testing.T) {
	pkgs := []depscan.Package{
		{Ecosystem: "Pub", Name: "http", Path: "app/pubspec.lock"},
		{Ecosystem: "Pub", Name: "path", Path: "app/pubspec.lock"},
		{Ecosystem: "Pub", Name: "args", Path: "tool/pubspec.lock"},
		{Ecosystem: "npm", Name: "a", Path: "package-lock.json"},
	}
	got := MissingDatabaseGaps([]string{"Pub", unoffered}, pkgs)
	want := []depscan.Gap{
		{Ecosystem: "Pub", Path: "app/pubspec.lock", Reason: depscan.ReasonNoDatabaseOffered, Packages: 2},
		{Ecosystem: "Pub", Path: "tool/pubspec.lock", Reason: depscan.ReasonNoDatabaseOffered, Packages: 1},
		{Ecosystem: unoffered, Reason: depscan.ReasonNoDatabaseOffered},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("gaps %+v, want %+v", got, want)
	}
}

// TestMissingDatabaseKeepsTheOtherResults: osv-scanner exits 127 when the
// only error it logged is an ecosystem with no local database; the run is
// read, the other ecosystems keep their results and the missing one is a
// gap, so the whole project is neither failed nor clean. Any other error
// line keeps it failed.
func TestMissingDatabaseKeepsTheOtherResults(t *testing.T) {
	missing := "could not find local databases for ecosystems: " + unoffered + "\n"
	cases := []struct {
		name    string
		code    int
		stderr  string
		failed  bool
		scanned bool // npm (its canary is in the fixture) is scanned in full
	}{
		{"exit 127, only the missing database", 127, missing, false, true},
		{"exit 1, only the missing database", 1, missing, false, true},
		{"exit 127 and an unplaced error", 127, missing + "Error: something went wrong\n", true, false},
		{"exit 127 naming an offered database", 127, "could not find local databases for ecosystems: npm\n", true, false},
		{"exit 127 with no stderr", 127, "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ex := &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
				if slices.Contains(p.Args, "--version") {
					return extrun.ExecFacts{Stdout: []byte("osv-scanner version: 2.6.0\n"), PeakChildren: -1}
				}
				return extrun.ExecFacts{ExitCode: c.code, Stdout: fixture(t), Stderr: []byte(c.stderr), PeakChildren: -1}
			}}
			res, err := newDriver(runnerWith(ex, true), allEpochs()).Scan(context.Background(), secscan.Target{ProjectRoot: root})
			if err != nil {
				t.Fatal(err)
			}
			cov := res.Coverage
			if (cov.Outcome == secscan.OutcomeFailed) != c.failed {
				t.Fatalf("coverage %+v, failed want %v", cov, c.failed)
			}
			if slices.Contains(cov.Scanned, "npm") != c.scanned {
				t.Fatalf("scanned %v, npm scanned want %v", cov.Scanned, c.scanned)
			}
			if c.failed {
				return
			}
			if cov.Outcome == secscan.OutcomeClean {
				t.Fatalf("coverage %+v: a missing database is never clean", cov)
			}
			found := false
			for _, s := range cov.Skipped {
				found = found || s.Reason == depscan.ReasonNoDatabaseOffered
			}
			if !found {
				t.Fatalf("skipped %+v lack the missing ecosystem's gap", cov.Skipped)
			}
		})
	}
}
