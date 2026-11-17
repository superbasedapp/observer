package secassesssvc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// refFileBody is one project file: line 3 holds the text the references cite.
func refFileBody(n int) string {
	return fmt.Sprintf("package f%d\n\nfunc handler() { /* %d */ }\n", n, n)
}

// writeRefFiles writes f1.go .. fN.go and returns the size of each (they are
// all the same size, below ten).
func writeRefFiles(t *testing.T, root string, n int) int {
	t.Helper()
	for i := 1; i <= n; i++ {
		writeProjectFile(t, root, fmt.Sprintf("f%d.go", i), refFileBody(i))
	}
	return len(refFileBody(1))
}

// refModel is a threat model with one component per cited path; every
// reference cites line 3 and a needle that is on it.
func refModel(paths ...string) string {
	comps := make([]string, len(paths))
	for i, p := range paths {
		comps[i] = fmt.Sprintf(`{"id":"c%d","name":"n","type":"service","paths":[{"path":%q,"line":3,"needle":"func handler"}]}`, i, p)
	}
	return `{"schema":"observer.threatmodel.v1","run_id":"` + svcRun + `","system":{"components":[` + strings.Join(comps, ",") + `]}}`
}

func fiveFiles() []string { return []string{"f1.go", "f2.go", "f3.go", "f4.go", "f5.go"} }

// checkNoUnlookedFound holds a validation to the rule that a reference earns
// "found" only on a file that was looked at: every reference whose path was
// stamped may be found, and every one whose path was not reads "unchecked".
func checkNoUnlookedFound(t *testing.T, tm *secassess.ThreatModelDoc, stamps []FileStamp) {
	t.Helper()
	looked := map[string]bool{}
	for _, s := range stamps {
		looked[s.Path] = true
	}
	for _, c := range tm.System.Components {
		for _, r := range c.Paths {
			switch {
			case looked[r.Path] && r.State == secassess.RefUnchecked:
				t.Errorf("%s was read and still reads unchecked", r.Path)
			case !looked[r.Path] && r.State != secassess.RefUnchecked:
				t.Errorf("%s was not looked at and reads %q", r.Path, r.State)
			case r.State == secassess.RefFound && !looked[r.Path]:
				t.Errorf("%s reads found without being looked at", r.Path)
			}
		}
	}
}

// TestRefBudgetDefaults: the budget's zero fields read as the defaults, one
// row per field and per way of not setting it.
func TestRefBudgetDefaults(t *testing.T) {
	d := DefaultRefBudget()
	if d.Files != 500 || d.TotalBytes != 128<<20 || d.Deadline != 10*time.Second || RefDeadline != 10*time.Second {
		t.Fatalf("defaults = %+v, deadline const %v", d, RefDeadline)
	}
	cases := []struct {
		name string
		in   RefBudget
		want RefBudget
	}{
		{"all zero", RefBudget{}, d},
		{"only the files set", RefBudget{Files: 7}, RefBudget{Files: 7, TotalBytes: d.TotalBytes, Deadline: d.Deadline}},
		{"only the bytes set", RefBudget{TotalBytes: 9}, RefBudget{Files: d.Files, TotalBytes: 9, Deadline: d.Deadline}},
		{"only the deadline set", RefBudget{Deadline: time.Second}, RefBudget{Files: d.Files, TotalBytes: d.TotalBytes, Deadline: time.Second}},
		{"negative fields read as the defaults", RefBudget{Files: -1, TotalBytes: -1, Deadline: -time.Second}, d},
		{"all set", RefBudget{Files: 1, TotalBytes: 2, Deadline: 3}, RefBudget{Files: 1, TotalBytes: 2, Deadline: 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.orDefault(); got != tc.want {
				t.Fatalf("orDefault() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestRefBudget: a model that cites more than the budget allows has the rest of
// its references read "unchecked" (never found), the validation is partial, and
// the tally says how many were not looked at. One row per limit and per side of
// each limit's edge. The first group goes through ValidateRun with the budget on
// ModelInput; the second drives the checker with an injected clock.
func TestRefBudget(t *testing.T) {
	root := t.TempDir()
	size := writeRefFiles(t, root, 5)
	run := []struct {
		name          string
		model         string
		budget        RefBudget
		wantFound     int
		wantUnchecked int
	}{
		{"two files of five", refModel(fiveFiles()...), RefBudget{Files: 2}, 2, 3},
		{"the limit is the number of files cited", refModel(fiveFiles()...), RefBudget{Files: 5}, 5, 0},
		{"one under the number of files cited", refModel(fiveFiles()...), RefBudget{Files: 4}, 4, 1},
		{"a single file", refModel(fiveFiles()...), RefBudget{Files: 1}, 1, 4},
		{"bytes under the files", refModel(fiveFiles()...), RefBudget{TotalBytes: int64(2*size + size/2)}, 2, 3},
		{"bytes exactly the files", refModel(fiveFiles()...), RefBudget{TotalBytes: int64(5 * size)}, 5, 0},
		{"bytes one under the files", refModel(fiveFiles()...), RefBudget{TotalBytes: int64(5*size - 1)}, 4, 1},
		{"bytes under one file", refModel(fiveFiles()...), RefBudget{TotalBytes: int64(size - 1)}, 0, 5},
		{"a budget that fits (zero fields are the defaults)", refModel(fiveFiles()...), RefBudget{}, 5, 0},
		{"one file cited many times counts once", refModel("f1.go", "f1.go", "f1.go", "f1.go", "f2.go", "f2.go"), RefBudget{Files: 2}, 6, 0},
		{"a repeated file after the budget is gone stays read", refModel("f1.go", "f2.go", "f3.go", "f1.go"), RefBudget{Files: 2}, 3, 1},
	}
	for _, tc := range run {
		t.Run(tc.name, func(t *testing.T) {
			writeModel(t, root, tc.model)
			in := validateOpts(root, modelRun(secassess.ContractThreatModel, true), false)
			in.Budget = tc.budget
			rec, v, err := ValidateRun(context.Background(), nil, in)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			rep := rec.Result.Report
			if rep.Refs.Found != tc.wantFound || rep.Refs.Unchecked != tc.wantUnchecked || rep.Refs.Missing != 0 {
				t.Fatalf("refs = %+v, want %d found and %d unchecked", rep.Refs, tc.wantFound, tc.wantUnchecked)
			}
			if v.Refs != rep.Refs {
				t.Errorf("the run's scalars carry %+v, the report %+v", v.Refs, rep.Refs)
			}
			wantState := secassess.ValidationValid
			if tc.wantUnchecked > 0 {
				wantState = secassess.ValidationPartial
			}
			if rep.State != wantState || v.State != string(wantState) {
				t.Errorf("state = %s (scalars %s), want %s", rep.State, v.State, wantState)
			}
			if tc.wantUnchecked > 0 && !hasIssueCode(rep, "ref_budget") {
				t.Errorf("no ref_budget issue: %+v", rep.Issues)
			}
			if tc.wantUnchecked == 0 && hasIssueCode(rep, "ref_budget") {
				t.Errorf("a ref_budget issue for a model within budget: %+v", rep.Issues)
			}
			checkNoUnlookedFound(t, rec.Result.TM, rec.Files)
		})
	}

	// The checker's own deadline, with an injected clock.
	base := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clockAfter := func(reads int) func() time.Time {
		calls := 0
		return func() time.Time {
			calls++
			if calls > reads {
				return base.Add(time.Hour)
			}
			return base
		}
	}
	direct := []struct {
		name          string
		deadline      time.Time
		now           func() time.Time
		wantFound     int
		wantUnchecked int
	}{
		{"the deadline is already past", base.Add(-time.Second), func() time.Time { return base }, 0, 5},
		{"the deadline passes after the second file", base.Add(time.Second), clockAfter(2), 2, 3},
		{"a deadline of exactly now is not past", base, func() time.Time { return base }, 5, 0},
		{"no deadline never expires", time.Time{}, func() time.Time { return base.Add(100 * time.Hour) }, 5, 0},
	}
	for _, tc := range direct {
		t.Run("checker: "+tc.name, func(t *testing.T) {
			chk := newChecker(t, root, tc.deadline, tc.now)
			opts := secassess.DefaultValidateOptions(secassess.ContractThreatModel, svcRun)
			opts.Refs = chk
			res := secassess.Validate([]byte(refModel(fiveFiles()...)), opts)
			rep := res.Report
			if rep.Refs.Found != tc.wantFound || rep.Refs.Unchecked != tc.wantUnchecked {
				t.Fatalf("refs = %+v, want %d found and %d unchecked", rep.Refs, tc.wantFound, tc.wantUnchecked)
			}
			wantState := secassess.ValidationValid
			if tc.wantUnchecked > 0 {
				wantState = secassess.ValidationPartial
			}
			if rep.State != wantState {
				t.Errorf("state = %s, want %s", rep.State, wantState)
			}
			if got := len(chk.Files()); got != tc.wantFound {
				t.Errorf("%d stamps, want %d", got, tc.wantFound)
			}
			checkNoUnlookedFound(t, res.TM, chk.Files())
		})
	}
}

// TestRefCheckerWithBudget: WithBudget sets the file and byte limits on a
// checker, returns the checker, and reads zero fields as the defaults.
func TestRefCheckerWithBudget(t *testing.T) {
	root := t.TempDir()
	size := writeRefFiles(t, root, 4)
	c := newChecker(t, root, time.Time{}, nil)
	if got := c.WithBudget(RefBudget{Files: 1}); got != c {
		t.Fatal("WithBudget does not return the checker")
	}
	if _, _, st := c.Lines("f1.go", 1, 1); st != secassess.LookupOK {
		t.Fatalf("the first file: %v", st)
	}
	if _, _, st := c.Lines("f2.go", 1, 1); st != secassess.LookupBudget {
		t.Fatalf("the second file past a one file budget: %v", st)
	}
	z := newChecker(t, root, time.Time{}, nil).WithBudget(RefBudget{})
	if z.maxFiles != maxRefFiles || z.maxTotal != maxRefTotalBytes {
		t.Fatalf("an empty budget set %d files and %d bytes", z.maxFiles, z.maxTotal)
	}
	b := newChecker(t, root, time.Time{}, nil).WithBudget(RefBudget{TotalBytes: int64(size)})
	if _, _, st := b.Lines("f1.go", 1, 1); st != secassess.LookupOK {
		t.Fatalf("a file that fills the byte budget: %v", st)
	}
	if _, _, st := b.Lines("f2.go", 1, 1); st != secassess.LookupBudget {
		t.Fatalf("a file past the byte budget: %v", st)
	}
	// A file that is not there is missing, not over budget, whatever the byte budget.
	if _, _, st := b.Lines("gone.go", 1, 1); st != secassess.LookupMissing {
		t.Fatalf("a missing file: %v", st)
	}
}

// TestStampsDriftWithinBudget: the drift check runs under the budget the
// validation ran with, but never looks at fewer files than were stamped, and a
// file it could not afford to read is "unknown, not changed" and not reported.
func TestStampsDriftWithinBudget(t *testing.T) {
	const n = 6
	changed := func(i int) string { return fmt.Sprintf("package f%d\n\nfunc changed() { /* %d */ }\n", i, i) }
	setup := func(t *testing.T) (root string, stamps []FileStamp, size int) {
		t.Helper()
		root = t.TempDir()
		size = writeRefFiles(t, root, n)
		c := newChecker(t, root, time.Time{}, nil)
		for i := 1; i <= n; i++ {
			c.Lines(fmt.Sprintf("f%d.go", i), 1, 1)
		}
		stamps = c.Files()
		if len(stamps) != n {
			t.Fatalf("%d stamps, want %d", len(stamps), n)
		}
		return root, stamps, size
	}
	rewrite := func(t *testing.T, root string, which ...int) {
		t.Helper()
		for _, i := range which {
			writeProjectFile(t, root, fmt.Sprintf("f%d.go", i), changed(i))
		}
	}
	if len(changed(1)) != len(refFileBody(1)) {
		t.Fatal("fixture: a changed file must keep its size")
	}
	cases := []struct {
		name   string
		budget func(size int) RefBudget
		edit   func(t *testing.T, root string)
		want   string // comma-joined drifted paths
	}{
		{
			"a files budget below the number of stamps still examines every stamp", func(int) RefBudget { return RefBudget{Files: 2} },
			func(t *testing.T, root string) { rewrite(t, root, 6) }, "f6.go",
		},
		{
			"a one file budget examines the changed ones past it", func(int) RefBudget { return RefBudget{Files: 1} },
			func(t *testing.T, root string) { rewrite(t, root, 3, 5) }, "f3.go,f5.go",
		},
		{
			"nothing changed: nothing reported under a tight files budget", func(int) RefBudget { return RefBudget{Files: 1} },
			func(*testing.T, string) {}, "",
		},
		{
			"a stamp past the byte budget is unknown, not changed", func(size int) RefBudget { return RefBudget{TotalBytes: int64(2*size + size/2)} },
			func(t *testing.T, root string) { rewrite(t, root, 1, 2, 3, 4, 5, 6) }, "f1.go,f2.go",
		},
		{
			"a byte budget that fits every stamp reports every change", func(size int) RefBudget { return RefBudget{TotalBytes: int64(n * size)} },
			func(t *testing.T, root string) { rewrite(t, root, 1, 2, 3, 4, 5, 6) }, "f1.go,f2.go,f3.go,f4.go,f5.go,f6.go",
		},
		{
			"nothing changed: nothing reported when no stamp fits the bytes", func(int) RefBudget { return RefBudget{TotalBytes: 1} },
			func(*testing.T, string) {}, "",
		},
		{
			"a changed file past the byte budget is not reported even when every file is", func(int) RefBudget { return RefBudget{TotalBytes: 1} },
			func(t *testing.T, root string) { rewrite(t, root, 1, 2, 3, 4, 5, 6) }, "",
		},
		{
			"a stamped file that is gone is reported, and costs no bytes", func(size int) RefBudget { return RefBudget{TotalBytes: int64(size)} },
			func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "f1.go")); err != nil {
					t.Fatal(err)
				}
				rewrite(t, root, 2, 3)
			}, "f1.go,f2.go",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, stamps, size := setup(t)
			tc.edit(t, root)
			got, err := StampsDriftWithin(root, stamps, tc.budget(size))
			if err != nil || strings.Join(got, ",") != tc.want {
				t.Fatalf("drift = %v (err %v), want %q", got, err, tc.want)
			}
		})
	}
	t.Run("StampsDrift is the default budget", func(t *testing.T) {
		root, stamps, _ := setup(t)
		rewrite(t, root, 2, 6)
		a, aerr := StampsDrift(root, stamps)
		b, berr := StampsDriftWithin(root, stamps, DefaultRefBudget())
		if aerr != nil || berr != nil || strings.Join(a, ",") != "f2.go,f6.go" || strings.Join(a, ",") != strings.Join(b, ",") {
			t.Fatalf("StampsDrift = %v (%v), StampsDriftWithin(default) = %v (%v)", a, aerr, b, berr)
		}
	})
}
