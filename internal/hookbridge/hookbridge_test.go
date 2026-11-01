package hookbridge

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHookExit(t *testing.T) {
	for in, want := range map[int]int{0: 0, 2: 2, 1: SentinelExit, 3: SentinelExit, 127: SentinelExit, -1: SentinelExit, SentinelExit: SentinelExit} {
		if got := HookExit(in); got != want {
			t.Errorf("HookExit(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestDecide has one row per decision-table rule plus the precedence rows.
// Every code wsl.exe could return for its own failure blocks; the hook's
// own answers (0, 2, the sentinel) pass, the sentinel as the host's
// non-blocking exit 1.
func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		run  Run
		want Decision
	}{
		{"wsl.exe could not be started", Run{Started: false, ExitCode: 0}, Decision{Outcome: OutcomeLaunchFailed}},
		{"the bridge's deadline fired", Run{Started: true, TimedOut: true, ExitCode: -1}, Decision{Outcome: OutcomeTimedOut}},
		{"a timeout wins over an allow code", Run{Started: true, TimedOut: true, ExitCode: 0}, Decision{Outcome: OutcomeTimedOut}},
		{"output too large to replay", Run{Started: true, ExitCode: 0, OutputOverflow: true}, Decision{Outcome: OutcomeOverflow}},
		{"hook allowed", Run{Started: true, ExitCode: 0}, Decision{Outcome: OutcomeAllow, Passthrough: true, ExitCode: 0}},
		{"hook blocked by exit code", Run{Started: true, ExitCode: 2}, Decision{Outcome: OutcomeHookBlock, Passthrough: true, ExitCode: 2}},
		{"hook answered non-blocking", Run{Started: true, ExitCode: SentinelExit}, Decision{Outcome: OutcomeHookNonBlocking, Passthrough: true, ExitCode: 1}},
		{"wsl.exe's own -1", Run{Started: true, ExitCode: -1}, Decision{Outcome: OutcomeHookNotStarted}},
		{"wsl.exe's own 1", Run{Started: true, ExitCode: 1}, Decision{Outcome: OutcomeHookNotStarted}},
		{"an HRESULT-sized code", Run{Started: true, ExitCode: -2147024894}, Decision{Outcome: OutcomeHookNotStarted}},
		{"bash's 127 (binary missing in the distro)", Run{Started: true, ExitCode: 127}, Decision{Outcome: OutcomeHookNotStarted}},
		{"not started wins over an allow code", Run{Started: false, ExitCode: 0}, Decision{Outcome: OutcomeLaunchFailed}},
	}
	for _, c := range cases {
		got := Decide(c.run)
		if got != c.want {
			t.Errorf("%s: Decide = %+v, want %+v", c.name, got, c.want)
		}
		if got.FailsClosed() == got.Passthrough {
			t.Errorf("%s: FailsClosed must be the opposite of Passthrough", c.name)
		}
	}
}

func TestEntryCommandAndArgv(t *testing.T) {
	e := Entry{Distro: "Ubuntu-24.04", Bin: "/opt/observer/bin/observer", Tool: "claude-code", Event: "pre-tool", Config: "/home/u/.observer/config.toml"}
	cmd, err := e.Command("C:/Users/u/AppData/Local/SuperBased/Observer/bin/observer.exe")
	if err != nil {
		t.Fatal(err)
	}
	want := "C:/Users/u/AppData/Local/SuperBased/Observer/bin/observer.exe hook-bridge --distro Ubuntu-24.04 --bin //opt/observer/bin/observer --tool claude-code --event pre-tool --config //home/u/.observer/config.toml"
	if cmd != want {
		t.Fatalf("Command =\n%s\nwant\n%s", cmd, want)
	}
	argv, err := e.Argv()
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"-d", "Ubuntu-24.04", "--exec", "/opt/observer/bin/observer", "hook", "claude-code", "pre-tool", "--config", "/home/u/.observer/config.toml", SentinelFlag}
	if !reflect.DeepEqual(argv, wantArgv) {
		t.Fatalf("Argv = %q", argv)
	}
	noCfg := e
	noCfg.Config = ""
	if a, _ := noCfg.Argv(); strings.Contains(strings.Join(a, " "), "--config") {
		t.Fatalf("no config must write no --config: %q", a)
	}
	for _, p := range e.Args() {
		if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
			t.Fatalf("arg %q would be rewritten by Git Bash's MSYS conversion", p)
		}
		if NormalizePath(p) != p && !strings.HasPrefix(p, "//") {
			t.Fatalf("NormalizePath changed %q", p)
		}
	}
	if NormalizePath("//opt/x") != "/opt/x" || NormalizePath("///x") != "///x" || NormalizePath("/x") != "/x" {
		t.Fatal("NormalizePath")
	}
}

// TestEntryRefusesUnsafeSpellings: everything the entry carries is written
// unquoted into a file three shells parse, so anything outside the closed
// spellings is refused (the registrar then keeps today's bridge).
func TestEntryRefusesUnsafeSpellings(t *testing.T) {
	ok := Entry{Distro: "Ubuntu", Bin: "/opt/o", Tool: "codex", Event: "PreToolUse"}
	for name, mutate := range map[string]func(*Entry){
		"distro with a space":    func(e *Entry) { e.Distro = "My Distro" },
		"distro with a quote":    func(e *Entry) { e.Distro = "U'b" },
		"distro starting dash":   func(e *Entry) { e.Distro = "-x" },
		"relative bin":           func(e *Entry) { e.Bin = "opt/o" },
		"bin with a space":       func(e *Entry) { e.Bin = "/opt/my o" },
		"bin with $":             func(e *Entry) { e.Bin = "/opt/$HOME/o" },
		"bin with ..":            func(e *Entry) { e.Bin = "/opt/../o" },
		"bin already doubled":    func(e *Entry) { e.Bin = "//opt/o" },
		"config with &":          func(e *Entry) { e.Config = "/a&b" },
		"event with a semicolon": func(e *Entry) { e.Event = "Pre;x" },
		"empty tool":             func(e *Entry) { e.Tool = "" },
	} {
		e := ok
		mutate(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for exe, want := range map[string]bool{
		"C:/Users/u/AppData/Local/SuperBased/Observer/bin/observer.exe": true,
		"C:/Users/John Smith/observer.exe":                              false,
		`C:\Users\u\observer.exe`:                                       false,
		"C:/x/observer.cmd":                                             false,
		"C:/x/../observer.exe":                                          false,
		"/mnt/c/x/observer.exe":                                         false,
		"C:/x/obs&erver.exe":                                            false,
	} {
		if ClosedWindowsExe(exe) != want {
			t.Errorf("ClosedWindowsExe(%q) != %v", exe, want)
		}
	}
	if WSLExe("") != `C:\Windows\System32\wsl.exe` || WSLExe(`D:\Win\`) != `D:\Win\System32\wsl.exe` {
		t.Fatal("WSLExe")
	}
}

// TestDeadline: below the host's own timeout, above the hook's 30 s
// watchdog where the host allows it, never above MaxDeadline.
func TestDeadline(t *testing.T) {
	for host, want := range map[time.Duration]time.Duration{
		60 * time.Second:  45 * time.Second, // Claude Code
		600 * time.Second: 45 * time.Second, // Codex
		30 * time.Second:  28 * time.Second,
		4 * time.Second:   2 * time.Second,
		0:                 MaxDeadline,
	} {
		if got := Deadline(host); got != want {
			t.Errorf("Deadline(%v) = %v, want %v", host, got, want)
		}
		if host > 0 && Deadline(host) >= host {
			t.Errorf("Deadline(%v) is not below the host timeout", host)
		}
	}
	if MaxDeadline <= 30*time.Second {
		t.Fatal("the bridge deadline must sit above the hook's own 30 s watchdog")
	}
}

func TestSplitWSLNotices(t *testing.T) {
	in := []byte("wsl: A localhost proxy configuration was detected\r\nblocked by rule R-101\nwsl: second notice\ntail with no newline")
	hook, notices := SplitWSLNotices(in)
	if string(hook) != "blocked by rule R-101\ntail with no newline" {
		t.Fatalf("hook part = %q", hook)
	}
	if string(notices) != "wsl: A localhost proxy configuration was detected\r\nwsl: second notice\n" {
		t.Fatalf("notices = %q", notices)
	}
	if h, n := SplitWSLNotices(nil); h != nil || n != nil {
		t.Fatal("empty in, empty out")
	}
}
