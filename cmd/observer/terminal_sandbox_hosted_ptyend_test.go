//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// Live run 2026-11-19, defect D7: hosted Daytona runs ended with "exit 255"
// and nothing said which side ended them. These pin the end record the
// in-box PTY helper sends and the attribution the home side makes of it.

func TestGuestPTYEndRecordSaysWhichSideEnded(t *testing.T) {
	exit255 := exec.Command("sh", "-c", "exit 255").Run()
	byHUP := exec.Command("sh", "-c", "kill -HUP $$").Run()
	cases := []struct {
		name    string
		err     error
		hungUp  bool
		sessErr error
		want    []string
	}{
		{"own exit 0", nil, false, nil, []string{"the agent exited with code 0 on its own"}},
		{"own exit 255", exit255, false, nil, []string{"the agent exited with code 255 on its own"}},
		{"hung up after the session ended", byHUP, true, errors.New("relaymux: read deadline exceeded"), []string{"session to the home side ended (relaymux: read deadline exceeded", "hung up the agent", "was ended by signal hangup"}},
	}
	for _, c := range cases {
		got := guestPTYEndRecord(c.err, c.hungUp, c.sessErr, 61*time.Second)
		if !strings.HasPrefix(got, relaymux.PTYEndPrefix) {
			t.Errorf("%s: %q has no end prefix", c.name, got)
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q lacks %q", c.name, got, w)
			}
		}
	}
}

func TestHostedPTYEndAttribution(t *testing.T) {
	cases := []struct {
		name    string
		f       hostedPTYEndFacts
		logHas  string
		sayHas  string
		sayNone bool
	}{
		{"no exit status: the cut", hostedPTYEndFacts{Vendor: "Daytona", WaitErr: errors.New("ended without an exit status")}, "without an exit status", "", true},
		{"the agent's own exit", hostedPTYEndFacts{Vendor: "Daytona", Code: 255, Record: "the agent exited with code 255 on its own", MuxErr: io.EOF}, "the box's helper says: the agent exited with code 255 on its own; the box closed the mux stream", "", true},
		{"the helper hung up", hostedPTYEndFacts{Vendor: "Daytona", Code: 129, Record: "the session to the home side ended (x), so the helper hung up the agent, which then was ended by signal hangup"}, "hung up", "lost its session to this machine", false},
		{"exit 255 with no record: the provider", hostedPTYEndFacts{Vendor: "Daytona", Code: 255, MuxErr: errors.New("relaymux: read deadline exceeded"), Quiet: 61 * time.Second}, "the provider's side ended the session, not the agent; the home side's mux had ended: relaymux: read deadline exceeded; the box's last frame came 1m1s before", "Daytona ended the agent's stream with exit 255", false},
		{"clean exit, older helper", hostedPTYEndFacts{Vendor: "Daytona", Code: 0}, "exit 0 and no end record", "", true},
	}
	for _, c := range cases {
		log, say := hostedPTYEndAttribution(c.f)
		if !strings.Contains(log, c.logHas) {
			t.Errorf("%s: log %q lacks %q", c.name, log, c.logHas)
		}
		if c.sayNone && say != "" {
			t.Errorf("%s: said %q", c.name, say)
		}
		if !c.sayNone && !strings.Contains(say, c.sayHas) {
			t.Errorf("%s: say %q lacks %q", c.name, say, c.sayHas)
		}
	}
}

func TestHostedPTYEndKeepsTheHelpersStderrAndRecord(t *testing.T) {
	e := &hostedPTYEnd{}
	_, _ = e.Write([]byte("observer sandbox --relay-stdio: something\nobserver sandbox --relay-stdio: " + relaymux.PTYEndPrefix + "the agent exited with code 255 on "))
	if e.endRecord() != "" {
		t.Fatal("a partial line was taken as the record")
	}
	_, _ = e.Write([]byte("its own\n"))
	if got := e.endRecord(); got != "the agent exited with code 255 on its own" {
		t.Fatalf("record %q", got)
	}
	e.note("PTY helper: " + relaymux.PTYEndPrefix + "the agent exited with code 3 on its own")
	if got := e.endRecord(); got != "the agent exited with code 3 on its own" {
		t.Fatalf("record from the mux %q", got)
	}
}
