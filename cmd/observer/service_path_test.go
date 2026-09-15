// service_path_test.go — pure-logic tests for the `observer service
// install` PATH-join/fallback and linger-detection decisions (DI-23).
// These never touch systemd, loginctl, or the filesystem: unitPathEnv is
// a plain string-slice→string join, and lingerAdvice is exercised
// directly with fabricated (out, err) pairs rather than through the real
// lingerRunner/exec.Command path, so the suite is Windows-safe and needs
// no live systemd --user manager.

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestUnitPathEnv(t *testing.T) {
	tests := []struct {
		name string
		dirs []string
		want string
	}{
		{name: "nil dirs falls back to empty", dirs: nil, want: ""},
		{name: "empty slice falls back to empty", dirs: []string{}, want: ""},
		{
			name: "single dir",
			dirs: []string{"/usr/bin"},
			want: "/usr/bin",
		},
		{
			name: "multiple dirs joined with colon, order preserved",
			dirs: []string{"/home/dev/.local/bin", "/home/dev/.hermes/node/bin", "/usr/bin", "/bin"},
			want: "/home/dev/.local/bin:/home/dev/.hermes/node/bin:/usr/bin:/bin",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unitPathEnv(tt.dirs); got != tt.want {
				t.Errorf("unitPathEnv(%v) = %q, want %q", tt.dirs, got, tt.want)
			}
		})
	}
}

func TestLingerAdvice(t *testing.T) {
	tests := []struct {
		name        string
		out         string
		err         error
		wantEmpty   bool
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:      "linger enabled prints nothing",
			out:       "yes",
			err:       nil,
			wantEmpty: true,
		},
		{
			name:      "linger enabled with trailing whitespace still prints nothing",
			out:       "yes\n",
			err:       nil,
			wantEmpty: true,
		},
		{
			name:        "linger disabled prints the enable-linger command",
			out:         "no",
			err:         nil,
			wantContain: []string{"loginctl enable-linger marmu", "Note:"},
			wantAbsent:  []string{"Warning:"},
		},
		{
			name:        "unexpected loginctl output is treated like disabled",
			out:         "",
			err:         nil,
			wantContain: []string{"loginctl enable-linger marmu", "Note:"},
		},
		{
			name:        "lookup error prints a warning, not an assertion",
			out:         "",
			err:         errors.New("exec: \"loginctl\": executable file not found in $PATH"),
			wantContain: []string{"Warning:", "loginctl enable-linger marmu", "could not check linger status"},
			wantAbsent:  []string{"Note:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lingerAdvice("marmu", tt.out, tt.err)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("lingerAdvice(%q, %v) = %q, want empty", tt.out, tt.err, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("lingerAdvice(%q, %v) = empty, want a note", tt.out, tt.err)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("lingerAdvice(%q, %v) = %q, want it to contain %q", tt.out, tt.err, got, want)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("lingerAdvice(%q, %v) = %q, unexpectedly contains %q", tt.out, tt.err, got, absent)
				}
			}
		})
	}
}

// TestLingerNoticeForUsesInjectedRunner pins lingerNoticeFor's wiring to
// lingerRunner (the package var), so a caller never needs to fake exec
// directly to test the "no"/"yes"/error command-printed/not-printed/
// warning outcomes end to end.
func TestLingerNoticeForUsesInjectedRunner(t *testing.T) {
	orig := lingerRunner
	defer func() { lingerRunner = orig }()

	tests := []struct {
		name      string
		fake      func(username string) (string, error)
		wantEmpty bool
		wantWarn  bool
	}{
		{
			name:      "yes -> no notice",
			fake:      func(string) (string, error) { return "yes\n", nil },
			wantEmpty: true,
		},
		{
			name: "no -> command printed",
			fake: func(string) (string, error) { return "no\n", nil },
		},
		{
			name:     "error -> warning printed",
			fake:     func(string) (string, error) { return "", errors.New("no systemd --user manager") },
			wantWarn: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lingerRunner = tt.fake
			got := lingerNoticeFor("marmu")
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("lingerNoticeFor = %q, want empty", got)
				}
				return
			}
			if got == "" {
				t.Fatalf("lingerNoticeFor = empty, want a printed notice")
			}
			if tt.wantWarn && !strings.HasPrefix(got, "Warning:") {
				t.Errorf("lingerNoticeFor = %q, want it to start with Warning:", got)
			}
			if !tt.wantWarn && !strings.HasPrefix(got, "Note:") {
				t.Errorf("lingerNoticeFor = %q, want it to start with Note:", got)
			}
		})
	}
}
