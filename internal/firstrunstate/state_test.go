package firstrunstate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

func TestPath(t *testing.T) {
	if got := Path(""); got != "" {
		t.Fatalf("Path(\"\") = %q", got)
	}
	want := filepath.Join("/x/y", Filename)
	if got := Path("/x/y/observer.db"); got != want {
		t.Fatalf("Path = %q, want %q", got, want)
	}
}

func TestRecordInstallOnce(t *testing.T) {
	cases := []struct {
		name  string
		fresh bool
		want  Install
		auto  bool
	}{
		{"empty database is fresh", true, InstallFresh, true},
		{"database with sessions is existing", false, InstallExisting, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := New(filepath.Join(t.TempDir(), Filename))
			st, err := s.RecordInstall(c.fresh, t0)
			if err != nil {
				t.Fatal(err)
			}
			if st.Install != c.want || AutoOpen(st) != c.auto {
				t.Fatalf("state = %+v auto=%v", st, AutoOpen(st))
			}
			// A later start never flips the recorded kind.
			st2, err := s.RecordInstall(!c.fresh, t0.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if st2.Install != c.want || !st2.RecordedAt.Equal(t0) {
				t.Fatalf("second record changed state: %+v", st2)
			}
			if got := s.Load(); got.Install != c.want {
				t.Fatalf("reloaded = %+v", got)
			}
		})
	}
}

func TestSeenClosesAutoOpenAndCanBeCleared(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), Filename))
	if _, err := s.RecordInstall(true, t0); err != nil {
		t.Fatal(err)
	}
	st, err := s.SetSeen(true, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Seen() || AutoOpen(st) {
		t.Fatalf("after seen: %+v auto=%v", st, AutoOpen(st))
	}
	// A second store over the same file (a second browser, a restart)
	// reads the same answer.
	if got := New(s.path).Load(); !got.Seen() || got.Install != InstallFresh {
		t.Fatalf("second reader = %+v", got)
	}
	st, err = s.SetSeen(false, t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if st.Seen() || !AutoOpen(st) {
		t.Fatalf("after clear: %+v", st)
	}
}

func TestUnreadableFileIsNothingRecorded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, Filename)
	for _, body := range []string{"not json", `{"schema":99,"install":"fresh"}`, `{"schema":1,"install":"weird"}`} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := New(p).Load(); got.Install != InstallUnknown || got.Seen() {
			t.Fatalf("body %q loaded as %+v", body, got)
		}
	}
}

func TestEmptyPathKeepsNothing(t *testing.T) {
	s := New("")
	st, err := s.RecordInstall(true, t0)
	if err != nil || st.Install != InstallUnknown {
		t.Fatalf("RecordInstall on empty path = %+v, %v", st, err)
	}
	st, err = s.SetSeen(true, t0)
	if err != nil || st.Seen() {
		t.Fatalf("SetSeen on empty path = %+v, %v", st, err)
	}
}

// TestSnoozeReplacesEarlierTime pins the Get started panel's return
// interval: each snooze restarts it, unlike Dismiss which keeps the first
// time, and a snooze persists across a reload of the file.
func TestSnoozeReplacesEarlierTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	s := New(path)
	if _, err := s.Snooze("get_started", t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(8 * 24 * time.Hour)
	st, err := s.Snooze("get_started", later)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Snoozed["get_started"]; !got.Equal(later) {
		t.Fatalf("snoozed at %v, want %v", got, later)
	}
	if got := New(path).Load().Snoozed["get_started"]; !got.Equal(later) {
		t.Fatalf("reloaded snooze %v, want %v", got, later)
	}
	if len(st.DismissedKeys()) != 0 {
		t.Fatalf("a snooze must not dismiss for good: %v", st.DismissedKeys())
	}
	if st, err := New("").Snooze("get_started", t0); err != nil || st.Snoozed != nil {
		t.Fatalf("empty path keeps nothing: %+v %v", st, err)
	}
}
