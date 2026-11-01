package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

func writeRelayJournal(t *testing.T, dir string, entries ...winrelay.Entry) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var data []byte
	for _, e := range entries {
		line, err := winrelay.Encode(e)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, line...)
	}
	if err := os.WriteFile(filepath.Join(dir, winrelay.JournalFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRelayJournalDirs(t *testing.T) {
	mine, theirs := t.TempDir(), t.TempDir()
	homes := []crossmount.HomeRoot{
		{Path: mine, OS: crossmount.OSWindows},
		{Path: theirs, OS: crossmount.OSWindows},
		{Path: "/home/u", OS: crossmount.OSLinux},
	}
	owned := func(h string) bool { return h == mine }
	cases := []struct {
		name  string
		goos  string
		isWSL bool
		want  []string
	}{
		{"windows host reads its own home", "windows", false, []string{filepath.Join(`C:\Users\u`, ".observer", "relay")}},
		{"WSL reads only the owned Windows home", "linux", true, []string{filepath.Join(mine, ".observer", "relay")}},
		{"native linux reads nothing", "linux", false, nil},
		{"darwin reads nothing", "darwin", false, nil},
	}
	for _, c := range cases {
		got := RelayJournalDirs(c.goos, `C:\Users\u`, c.isWSL, homes, owned)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if got := RelayJournalDirs("linux", "", true, homes, nil); got != nil {
		t.Errorf("no ownership seam must read no foreign home, got %v", got)
	}
}

func TestRelayChecks(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	writeRelayJournal(t, dir,
		winrelay.Entry{At: now.Add(-time.Hour), Tool: "claude-code", Upstream: "api.anthropic.com", Method: "POST", Path: "/v1/messages", Reason: winrelay.ReasonProxyUnreachable},
		winrelay.Entry{At: now.Add(-30 * 24 * time.Hour), Tool: "claude-code", Upstream: "api.anthropic.com", Method: "POST", Path: "/v1/messages", Reason: winrelay.ReasonProxyUnreachable},
	)
	j := ReadRelayJournal([]string{dir}, now.Add(-7*24*time.Hour))
	if !j.Found || j.Summary.Total() != 1 {
		t.Fatalf("journal = %+v", j)
	}

	if got := relayChecks("linux", false, j); got != nil {
		t.Fatalf("a native Linux node has no relay rows, got %+v", got)
	}
	got := relayChecks("linux", true, j)
	if len(got) != 2 || got[0].Name != relayGateCheckName || got[0].Status != StatusOK || !strings.Contains(got[0].Message, "built, waiting on live check LC6 and LC14") {
		t.Fatalf("gate row = %+v", got)
	}
	if got[1].Name != relayBypassCheckName || got[1].Status != StatusWarn || !strings.Contains(got[1].Message, "1 request(s) bypassed") || !strings.Contains(strings.Join(got[1].Details, "\n"), "claude-code: 1 bypass(es)") {
		t.Fatalf("bypass row = %+v", got[1])
	}

	clean := relayChecks("windows", false, ReadRelayJournal([]string{dir}, now))
	if clean[1].Status != StatusOK {
		t.Fatalf("no bypass in the window must read OK, got %+v", clean[1])
	}
	if none := relayChecks("windows", false, ReadRelayJournal([]string{t.TempDir()}, now)); len(none) != 1 {
		t.Fatalf("no journal means no bypass row, got %+v", none)
	}
}

func TestRelayJournalUnreadableWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, winrelay.JournalFile), 0o700); err != nil {
		t.Fatal(err)
	}
	j := ReadRelayJournal([]string{dir}, time.Time{})
	if !j.Found || len(j.Unreadable) != 1 {
		t.Fatalf("journal = %+v", j)
	}
	got := relayChecks("linux", true, j)
	if got[1].Status != StatusWarn || !strings.Contains(strings.Join(got[1].Details, "\n"), "unreadable") {
		t.Fatalf("an unreadable journal must WARN, got %+v", got[1])
	}
}

// TestRelayOwnHome pins the one home rule the relay writer and its readers
// share: the account's real home from the pinned-home lookup, refused when
// unset, relative or isolated (the lookup then answers "").
func TestRelayOwnHome(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		name, goos string
		vars       map[string]string
		want       string
	}{
		{"windows USERPROFILE", "windows", map[string]string{"USERPROFILE": `C:\Users\u`, "HOME": "/home/x"}, `C:\Users\u`},
		{"linux HOME", "linux", map[string]string{"HOME": "/home/u"}, "/home/u"},
		{"isolated (no lookup answer)", "windows", nil, ""},
		{"relative windows home", "windows", map[string]string{"USERPROFILE": `Users\u`}, ""},
		{"relative posix home", "linux", map[string]string{"HOME": "home/u"}, ""},
	}
	for _, c := range cases {
		got, err := relayOwnHomeFrom(c.goos, env(c.vars))
		if got != c.want || (c.want == "") != (err != nil) {
			t.Errorf("%s: %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	if winrelayJournalDir := RelayJournalDirs("windows", `C:\Users\u`, false, nil, nil); len(winrelayJournalDir) != 1 {
		t.Fatal("the windows reader must read the writer's directory")
	}
}
