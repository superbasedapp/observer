package firstrunstate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/planechoice"
)

func TestFocusSetsClearsAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	s := New(path)
	if st, err := s.SetFocus(planechoice.ChoiceApps); err != nil || st.Focus != planechoice.ChoiceApps {
		t.Fatalf("SetFocus apps: %+v %v", st, err)
	}
	if got := New(path).Load().Focus; got != planechoice.ChoiceApps {
		t.Fatalf("reloaded focus = %q", got)
	}
	if _, err := s.SetFocus("everything"); err == nil {
		t.Fatal("an unknown choice was stored")
	}
	if st, err := s.SetFocus(planechoice.ChoiceNone); err != nil || st.Focus != planechoice.ChoiceNone {
		t.Fatalf("clear: %+v %v", st, err)
	}
}

func TestIntentRecordedOnceFirstWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	s := New(path)
	st, rec, err := s.RecordIntent(planechoice.ChoiceApps, planechoice.SourceConnect, t0)
	if err != nil || !rec || st.IntentChoice() != planechoice.ChoiceApps {
		t.Fatalf("first: %+v %v %v", st, rec, err)
	}
	st, rec, err = s.RecordIntent(planechoice.ChoiceCoding, planechoice.SourceForLink, t0)
	if err != nil || rec || st.IntentChoice() != planechoice.ChoiceApps || st.Intent.Source != planechoice.SourceConnect {
		t.Fatalf("second replaced the first: %+v %v %v", st, rec, err)
	}
	if _, _, err := s.RecordIntent("apps", "web", t0); err == nil {
		t.Fatal("an unknown source was accepted")
	}
	if _, _, err := s.RecordIntent("apps/../x", planechoice.SourceForLink, t0); err == nil {
		t.Fatal("an unknown choice was accepted")
	}
}

func TestHandEditedFocusAndIntentReadAsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	body := `{"schema":1,"focus":"everything","intent":{"choice":"apps","source":"web","at":"2026-11-20T00:00:00Z"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	st := New(path).Load()
	if st.Focus != planechoice.ChoiceNone || st.Intent != nil {
		t.Fatalf("unknown values survived the read: %+v", st)
	}
}

func TestOlderFileReadsWithoutFocus(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	if err := os.WriteFile(path, []byte(`{"schema":1,"install":"fresh"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st := New(path).Load()
	if st.Install != InstallFresh || st.Focus != "" || st.Intent != nil {
		t.Fatalf("%+v", st)
	}
}
