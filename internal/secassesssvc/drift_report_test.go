package secassesssvc

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestStampsDriftReportNamesUnread: a stamp the byte budget ran out on is
// reported as unread (unknown), not folded into "unchanged", so the fix route
// can say Observer could not look; StampsDriftWithin still answers only the
// changed ones.
func TestStampsDriftReportNamesUnread(t *testing.T) {
	const n = 6
	root := t.TempDir()
	size := writeRefFiles(t, root, n)
	c := newChecker(t, root, time.Time{}, nil)
	for i := 1; i <= n; i++ {
		c.Lines(fmt.Sprintf("f%d.go", i), 1, 1)
	}
	stamps := c.Files()
	for i := 1; i <= n; i++ {
		writeProjectFile(t, root, fmt.Sprintf("f%d.go", i), fmt.Sprintf("package f%d\n\nfunc changed() { /* %d */ }\n", i, i))
	}
	budget := RefBudget{TotalBytes: int64(2*size + size/2)}
	rep, err := StampsDriftReport(root, stamps, budget)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rep.Changed, ","); got != "f1.go,f2.go" {
		t.Errorf("changed = %q", got)
	}
	if got := strings.Join(rep.Unread, ","); got != "f3.go,f4.go,f5.go,f6.go" {
		t.Errorf("unread = %q", got)
	}
	if only, err := StampsDriftWithin(root, stamps, budget); err != nil || strings.Join(only, ",") != "f1.go,f2.go" {
		t.Errorf("StampsDriftWithin = %v, %v", only, err)
	}
	// Nothing to look at: an empty report.
	if rep, err := StampsDriftReport(root, nil, budget); err != nil || rep.Changed != nil || rep.Unread != nil {
		t.Errorf("no stamps: %+v, %v", rep, err)
	}
	// A folder that is gone: every stamp changed, none unread.
	if rep, err := StampsDriftReport(root+"-gone", stamps, budget); err != nil || len(rep.Changed) != n || len(rep.Unread) != 0 {
		t.Errorf("a folder that is gone: %+v, %v", rep, err)
	}
}
