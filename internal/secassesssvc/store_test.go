package secassesssvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

func runID(n int) string { return fmt.Sprintf("%016x", n) }

func TestRecordGetRecent(t *testing.T) {
	st := New(Path(filepath.Join(t.TempDir(), "observer.db")))
	now := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	a, err := st.Record(Run{ID: runID(1), Kind: "pentest_local", Tool: "claude-code", ProjectRootHash: "h1", Target: "http://localhost:3000/", Sandboxed: true, Backend: "bwrap", Tier: "proxy_only"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !a.CreatedAt.Equal(now) {
		t.Errorf("created = %v", a.CreatedAt)
	}
	if _, err := st.Record(Run{ID: runID(2), Kind: "threat_model"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := New(st.path).Recent(10)
	if len(got) != 2 || got[0].Kind != "threat_model" || got[1].ID != runID(1) || got[1].Target != "http://localhost:3000/" || !got[1].Sandboxed {
		t.Fatalf("recent = %+v", got)
	}
	if r, ok := st.Get(runID(1)); !ok || r.Backend != "bwrap" {
		t.Errorf("get = %+v %v", r, ok)
	}
	if _, ok := st.Get(runID(9)); ok {
		t.Error("an unknown run resolved")
	}
	if !st.Exists(runID(2)) || st.Exists(runID(3)) {
		t.Error("Exists is wrong")
	}
	if n := len(st.Recent(1)); n != 1 {
		t.Errorf("Recent(1) = %d", n)
	}
}

func TestRecordRefusals(t *testing.T) {
	st := New(filepath.Join(t.TempDir(), Filename))
	if _, err := st.Record(Run{ID: "../etc"}, time.Now()); err == nil {
		t.Error("a bad id was recorded")
	}
	if _, err := st.Record(Run{ID: runID(1)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Record(Run{ID: runID(1)}, time.Now()); !errors.Is(err, ErrDuplicateRun) {
		t.Errorf("duplicate: %v", err)
	}
}

func TestBounds(t *testing.T) {
	st := New(filepath.Join(t.TempDir(), Filename))
	for i := 0; i < MaxRuns+3; i++ {
		if _, err := st.Record(Run{ID: runID(i), Tool: strings.Repeat("t", 999)}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	all := st.Recent(MaxRuns + 10)
	if len(all) != MaxRuns || all[0].ID != runID(MaxRuns+2) || all[len(all)-1].ID != runID(3) {
		t.Fatalf("kept %d, newest %s oldest %s", len(all), all[0].ID, all[len(all)-1].ID)
	}
	if len(all[0].Tool) != maxField {
		t.Errorf("tool kept %d bytes", len(all[0].Tool))
	}
}

func TestSetImport(t *testing.T) {
	st := New(filepath.Join(t.TempDir(), Filename))
	if _, err := st.Record(Run{ID: runID(1), Kind: "threat_model"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	many := map[string]int{}
	for i := 0; i < 50; i++ {
		many[fmt.Sprintf("reason_%d", i)] = i
	}
	rec := ImportRecord{At: time.Now(), Outcome: "imported", Findings: 3, New: 2, Refused: many, Reason: strings.Repeat("x", 999)}
	if err := st.SetImport(runID(1), rec); err != nil {
		t.Fatal(err)
	}
	r, _ := st.Get(runID(1))
	if r.Import == nil || r.Import.Findings != 3 || r.Import.New != 2 || len(r.Import.Refused) != 32 || len(r.Import.Reason) != maxField {
		t.Fatalf("import = %+v", r.Import)
	}
	if err := st.SetImport(runID(9), rec); err == nil {
		t.Error("an import was set on an unknown run")
	}
}

func TestUnreadableFileHoldsNothing(t *testing.T) {
	cases := map[string]string{
		"garbage":      "{not json",
		"other schema": `{"schema":99,"runs":[{"id":"x"}]}`,
		"oversize":     strings.Repeat("x", maxBytes+10),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), Filename)
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := New(p).Recent(5); len(got) != 0 {
				t.Errorf("recent = %+v", got)
			}
		})
	}
	if got := New("").Recent(5); len(got) != 0 {
		t.Errorf("empty path recent = %+v", got)
	}
	if a, err := New("").Record(Run{ID: runID(1)}, time.Now()); err != nil || a.ID == "" {
		t.Errorf("empty path record = %+v, %v", a, err)
	}
	if err := New("").SetImport(runID(1), ImportRecord{}); err != nil {
		t.Errorf("empty path SetImport: %v", err)
	}
}

func TestSharedIsOnePerPath(t *testing.T) {
	p := filepath.Join(t.TempDir(), Filename)
	first, second := Shared(p), Shared(p)
	if first != second {
		t.Error("two stores for one path")
	}
	if first == Shared(p+"2") {
		t.Error("one store for two paths")
	}
	noneA, noneB := Shared(""), Shared("")
	if noneA == noneB {
		t.Error("an empty path must not share state")
	}
	if Path("") != "" || filepath.Base(Path("/x/observer.db")) != Filename {
		t.Error("Path is wrong")
	}
}

func TestNewRunID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id := NewRunID()
		if !secassess.ValidRunID(id) || seen[id] {
			t.Fatalf("bad or repeated run id %q", id)
		}
		seen[id] = true
	}
}
