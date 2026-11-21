package secfixstate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordAndRecent(t *testing.T) {
	dir := t.TempDir()
	st := New(Path(filepath.Join(dir, "observer.db")))
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	a, err := st.Record(Attempt{Tool: "claude-code", ProjectRootHash: "h1", Seeded: true, FindingIDs: []string{"f1", "", "f2"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.ID) != 16 || !a.CreatedAt.Equal(now) {
		t.Errorf("attempt = %+v", a)
	}
	if strings.Join(a.FindingIDs, ",") != "f1,f2" {
		t.Errorf("ids = %v", a.FindingIDs)
	}
	if _, err := st.Record(Attempt{Tool: "codex", ProjectRootHash: "h2"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := New(st.path).Recent(10)
	if len(got) != 2 || got[0].Tool != "codex" || got[1].ID != a.ID || !got[1].Seeded {
		t.Fatalf("recent = %+v", got)
	}
	if n := len(st.Recent(1)); n != 1 {
		t.Errorf("Recent(1) = %d", n)
	}
}

func TestBounds(t *testing.T) {
	st := New(filepath.Join(t.TempDir(), Filename))
	now := time.Now()
	var many []string
	for i := 0; i < MaxFindingIDs+5; i++ {
		many = append(many, fmt.Sprintf("f%d", i))
	}
	for i := 0; i < MaxAttempts+3; i++ {
		if _, err := st.Record(Attempt{ID: fmt.Sprintf("a%d", i), Tool: strings.Repeat("t", 999), FindingIDs: many}, now); err != nil {
			t.Fatal(err)
		}
	}
	all := st.Recent(MaxAttempts + 10)
	if len(all) != MaxAttempts {
		t.Fatalf("kept %d, want %d", len(all), MaxAttempts)
	}
	if all[0].ID != fmt.Sprintf("a%d", MaxAttempts+2) || all[len(all)-1].ID != "a3" {
		t.Errorf("newest %s oldest %s", all[0].ID, all[len(all)-1].ID)
	}
	if len(all[0].FindingIDs) != MaxFindingIDs || len(all[0].Tool) != maxField {
		t.Errorf("caps: %d ids, tool %d bytes", len(all[0].FindingIDs), len(all[0].Tool))
	}
}

func TestUnreadableFileHoldsNothing(t *testing.T) {
	cases := map[string]string{
		"garbage":      "{not json",
		"other schema": `{"schema":99,"attempts":[{"id":"x"}]}`,
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
	if a, err := New("").Record(Attempt{Tool: "x"}, time.Now()); err != nil || a.ID == "" {
		t.Errorf("empty path record = %+v, %v", a, err)
	}
}
