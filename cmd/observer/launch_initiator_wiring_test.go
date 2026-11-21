//go:build !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/peerproc"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// launch_initiator_wiring_test.go pins lane cli-2 fixes-3, audit L1: the
// production wiring, not a resolver a test builds itself. It fails if the
// daemon's resolver loses one of its process readers (the environment read
// of the agent marker, the start token, the ancestry walk) or its daemon
// pid, if the confirmer or the launch origin newLaunchControl wires stops
// passing the client's hint or the start check, or if the attach host stops
// snapshotting its caller at accept.

// sameFunc reports whether two function values are the same function.
func sameFunc(a, b any) bool { return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer() }

// wiringStack is a terminal stack with no launches, enough to build the
// daemon's resolvers.
func wiringStack() *terminalStack {
	return &terminalStack{
		svc: termsvc.New(termsvc.Options{}),
		mgr: termsession.NewManager(termsession.Options{Spawner: fakeSpawner{}}),
	}
}

// TestProductionInitiatorReadsTheCaller pins the daemon's resolver.
func TestProductionInitiatorReadsTheCaller(t *testing.T) {
	li := wiringStack().launchInitiator()
	for _, r := range []struct {
		name      string
		got, want any
	}{
		{"envMarker", li.envMarker, readSessionMarker},
		{"startOf", li.startOf, peerproc.StartToken},
		{"ancestors", li.ancestors, peerproc.Ancestors},
	} {
		if reflect.ValueOf(r.got).IsNil() || !sameFunc(r.got, r.want) {
			t.Errorf("the daemon's launchInitiator does not read %s through its production reader", r.name)
		}
	}
	if li.daemonPID != os.Getpid() {
		t.Errorf("the daemon's launchInitiator daemonPID = %d, want this process %d", li.daemonPID, os.Getpid())
	}
	self := withProcessReaders(launchInitiator{})
	if self.envMarker == nil || self.startOf == nil || self.ancestors == nil || self.daemonPID != 0 {
		t.Errorf("withProcessReaders lost a reader: %+v", self)
	}
}

// TestProductionConfirmerAndOriginPassTheHint drives the confirmer and the
// launch origin that newLaunchControl wires, and the attach host's
// snapshot and origin.
func TestProductionConfirmerAndOriginPassTheHint(t *testing.T) {
	start, ok := peerproc.StartToken(os.Getpid())
	if !ok {
		t.Skip("no process start token on this platform")
	}
	stack := wiringStack()
	c := newLaunchControl(stack)
	live := callerCtx(os.Getpid(), start)
	hinted := attachsock.WithCallerHint(live, attachsock.CallerHint{AgentEnv: true, Session: "sess-hint"})
	f := c.confirmer(hinted)
	if f.CallerGone || f.Origin != (termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-hint"}) {
		t.Fatalf("the wired confirmer's facts = %+v, want the hint's agent", f)
	}
	if ok, _, _ := agentlaunch.MayConfirm(f); ok {
		t.Fatal("the wired confirmer let a hinted agent confirm")
	}
	o, err := c.origin(live, attachsock.LaunchSpec{Tool: "claude", AgentEnv: true, AgentEnvSession: "sess-spec"})
	if err != nil || o != (termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-spec"}) {
		t.Fatalf("the wired launch origin = %+v %v, want the spec's agent", o, err)
	}
	pid, tok := goneCaller(t)
	if f := c.confirmer(callerCtx(pid, tok)); !f.CallerGone {
		t.Fatalf("the wired confirmer judged a gone caller: %+v", f)
	}
	if _, err := c.origin(callerCtx(pid, tok), attachsock.LaunchSpec{Tool: "claude"}); agentlaunch.CodeOf(err) != agentlaunch.CodeCallerGone {
		t.Fatalf("the wired launch origin for a gone caller = %v", err)
	}

	host := stack.attachHost()
	cs, ok := host.(attachsock.CallerSnapshotter)
	if !ok {
		t.Fatal("the attach host is not an attachsock.CallerSnapshotter")
	}
	if _, ok := seenAtConnect(cs.SnapshotCaller(context.Background(), os.Getpid()), os.Getpid()); !ok {
		t.Fatal("the attach host does not snapshot its caller at accept")
	}
	h, ok := host.(*attachHost)
	if !ok {
		t.Fatalf("the attach host is a %T", host)
	}
	o, err = h.origin(live, attachsock.SpawnRequest{Tool: "claude-code", AgentEnv: true, AgentEnvSession: "sess-attach"})
	if err != nil || o != (termrun.Origin{Initiator: termrun.InitiatorAgent, ParentSessionID: "sess-attach"}) {
		t.Fatalf("the attach host's origin = %+v %v", o, err)
	}
	if _, err := h.origin(callerCtx(pid, tok), attachsock.SpawnRequest{Tool: "claude-code"}); agentlaunch.CodeOf(err) != agentlaunch.CodeCallerGone {
		t.Fatalf("the attach host's origin for a gone caller = %v", err)
	}
}
