package sandboxrelay

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestPathSyntaxClean is the path syntax table (Windows 11 Pro run 3): each
// row's absolute-path rule, its clean spelling, and the paths it refuses.
func TestPathSyntaxClean(t *testing.T) {
	for _, c := range []struct {
		syn   PathSyntax
		in    string
		clean string
		ok    bool
		exact bool
	}{
		{PosixPaths, "/", "/", true, true},
		{PosixPaths, "/home/op/work", "/home/op/work", true, true},
		{PosixPaths, "/home/op/work/", "/home/op/work", true, false},
		{PosixPaths, "/a//b", "", false, false},
		{PosixPaths, "/a/./b", "", false, false},
		{PosixPaths, "/a/../b", "", false, false},
		{PosixPaths, "work", "", false, false},
		{PosixPaths, `C:\Users\op\work`, "", false, false},
		{PosixPaths, "/a\x00b", "", false, false},
		{WindowsPaths, `C:\Users\op\work`, `C:\Users\op\work`, true, true},
		{WindowsPaths, `c:\users\op`, `c:\users\op`, true, true},
		{WindowsPaths, `C:\`, `C:\`, true, true},
		{WindowsPaths, `C:\Users\op\work\`, `C:\Users\op\work`, true, false},
		{WindowsPaths, `C:/Users/op/work`, `C:\Users\op\work`, true, false},
		{WindowsPaths, `C:\Users\..\Windows`, "", false, false},
		{WindowsPaths, `C:\Users\.\op`, "", false, false},
		{WindowsPaths, `C:\a\\b`, "", false, false},
		{WindowsPaths, `C:relative`, "", false, false},
		{WindowsPaths, `\Users\op`, "", false, false},
		{WindowsPaths, `\\server\share\x`, "", false, false},
		{WindowsPaths, `\\?\C:\Windows`, "", false, false},
		{WindowsPaths, `\\.\pipe\x`, "", false, false},
		{WindowsPaths, `C:\file.txt:stream`, "", false, false},
		{WindowsPaths, `C:\a*b`, "", false, false},
		{WindowsPaths, `1:\x`, "", false, false},
		{WindowsPaths, "/home/op", "", false, false},
		{PathSyntax{}, "/x", "", false, false},
	} {
		got, ok := c.syn.Clean(c.in)
		if ok != c.ok || got != c.clean {
			t.Errorf("%s Clean(%q) = %q %v, want %q %v", c.syn.Name, c.in, got, ok, c.clean, c.ok)
		}
		if c.syn.IsClean(c.in) != c.exact {
			t.Errorf("%s IsClean(%q) = %v", c.syn.Name, c.in, !c.exact)
		}
	}
}

// TestPathSyntaxWithin: containment in each syntax, a Windows one with its
// own separator and case-insensitively, never a sibling sharing a prefix.
func TestPathSyntaxWithin(t *testing.T) {
	for _, c := range []struct {
		syn     PathSyntax
		p, root string
		want    bool
	}{
		{PosixPaths, "/w", "/w", true},
		{PosixPaths, "/w/sub", "/w", true},
		{PosixPaths, "/work", "/w", false},
		{PosixPaths, "/W/sub", "/w", false},
		{PosixPaths, "/anything", "/", true},
		{WindowsPaths, `C:\Users\op\work`, `C:\Users\op\work`, true},
		{WindowsPaths, `C:\Users\op\work\sub`, `C:\Users\op\work`, true},
		{WindowsPaths, `c:\USERS\OP\WORK\sub`, `C:\Users\op\work`, true},
		{WindowsPaths, `C:\Users\op\workshop`, `C:\Users\op\work`, false},
		{WindowsPaths, `C:/Users/op/work/sub`, `C:\Users\op\work`, false},
		{WindowsPaths, `D:\x`, `C:\`, false},
		{WindowsPaths, `C:\x`, `C:\`, true},
		{WindowsPaths, `C:\x`, `c:\`, true},
	} {
		if got := c.syn.Within(c.p, c.root); got != c.want {
			t.Errorf("%s Within(%q, %q) = %v", c.syn.Name, c.p, c.root, got)
		}
	}
}

// TestHostPathsFollowsTheSeparator: the host's row is chosen by its path
// separator, never an OS name, and rules with no syntax use it.
func TestHostPathsFollowsTheSeparator(t *testing.T) {
	if HostPaths().Separator != filepath.Separator {
		t.Fatalf("host syntax %s on a %q host", HostPaths().Name, filepath.Separator)
	}
	if PathsFor('\\').Name != "windows" || PathsFor('/').Name != "posix" || PathsFor(':').Name != "posix" {
		t.Fatal("the separator table")
	}
	if (RequestRules{}).Syntax().Name != HostPaths().Name || (RequestRules{Paths: WindowsPaths}).Syntax().Name != "windows" {
		t.Fatal("the rules' syntax")
	}
}

// TestRequestCwdInTheHostSyntax is the run 3 cause: a Windows box's working
// directory passes the schema under the Windows syntax; under the POSIX
// syntax (the only one the schema knew) it is refused, which is what made
// the host helper close every Windows box's stream.
func TestRequestCwdInTheHostSyntax(t *testing.T) {
	win := RequestRules{EnvAllowed: func(string) bool { return true }, Paths: WindowsPaths}
	posix := win
	posix.Paths = PosixPaths
	for _, c := range []struct {
		rules RequestRules
		cwd   string
		ok    bool
	}{
		{win, `C:\Users\winagent\AppData\Local\Temp\sbo-p6-iso\work`, true},
		{win, `C:\Users\op\work\`, false},
		{win, `C:/Users/op/work`, false},
		{win, `\\server\share`, false},
		{posix, `C:\Users\op\work`, false},
		{posix, "/home/op/work", true},
	} {
		msg, err := EncodeHookRequest(HookRequest{Kind: KindLaunchGate, Args: []string{"claude-code"}, Cwd: c.cwd, Stdin: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		_, derr := DecodeHookRequest(msg, c.rules)
		done, herr := CheckHookRequestHead(msg, c.rules)
		if (derr == nil) != c.ok || (herr == nil && done) != c.ok {
			t.Errorf("%s cwd %q: decode %v head %v", c.rules.Syntax().Name, c.cwd, derr, herr)
		}
		if !c.ok && (derr == nil || !strings.Contains(derr.Error(), c.rules.Syntax().Name)) {
			t.Errorf("the refusal names no syntax: %v", derr)
		}
	}
}

// TestHopAnswerSchema: a hop answer is a current-version answer carrying
// only an on-wire hop and its bounded, printable address and detail.
func TestHopAnswerSchema(t *testing.T) {
	for _, c := range []struct {
		name string
		r    HookResponse
		ok   bool
	}{
		{"a daemon hop", HookResponse{Hop: HopDaemonConnect, HopAddr: `\\.\pipe\observer-relay-abc`, HopDetail: "the system cannot find the file"}, true},
		{"a helper refusal", HookResponse{Hop: HopHelperRequest, HopDetail: "cwd"}, true},
		{"a box-side hop", HookResponse{Hop: HopBoxClosed}, false},
		{"an unknown hop", HookResponse{Hop: "elsewhere"}, false},
		{"a hop with output", HookResponse{Hop: HopDaemonAnswer, Stderr: []byte("x")}, false},
		{"a hop with an exit", HookResponse{Hop: HopDaemonAnswer, Exit: 1}, false},
		{"a hop with a refusal", HookResponse{Hop: HopDaemonAnswer, Refused: RefusedPath}, false},
		{"a version 1 hop", HookResponse{V: LegacyHookVersion, Hop: HopDaemonAnswer}, false},
		{"a control character", HookResponse{Hop: HopDaemonAnswer, HopDetail: "a\nb"}, false},
		{"an address with no hop", HookResponse{HopAddr: "x"}, false},
		{"over the bound", HookResponse{Hop: HopDaemonAnswer, HopDetail: strings.Repeat("d", MaxHopText+1)}, false},
	} {
		msg, err := EncodeHookResponse(c.r)
		if (err == nil) != c.ok {
			t.Errorf("%s: encode %v", c.name, err)
			continue
		}
		if !c.ok {
			continue
		}
		got, err := DecodeHookResponse(msg)
		if err != nil || got.Hop != c.r.Hop || got.HopAddr != c.r.HopAddr || got.HopDetail != c.r.HopDetail {
			t.Errorf("%s: decode %+v %v", c.name, got, err)
		}
		var he *HopError
		if !errors.As(got.HopErr(), &he) || he.Hop != c.r.Hop {
			t.Errorf("%s: HopErr %v", c.name, got.HopErr())
		}
	}
	if (HookResponse{}).HopErr() != nil {
		t.Fatal("an answer with no hop is an error")
	}
	if got := HopText("a\x01b\nc" + strings.Repeat("x", MaxHopText)); len(got) != MaxHopText || strings.ContainsAny(got, "\x01\n") {
		t.Fatalf("HopText %q", got)
	}
}
