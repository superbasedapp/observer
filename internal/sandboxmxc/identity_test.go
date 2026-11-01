package sandboxmxc

import (
	"errors"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestBoxSID is BoxSID's table: only an AppContainer process running the
// inner image that really descends from the run's wxc-exec names the box's
// container; two containers are never picked from.
func TestBoxSID(t *testing.T) {
	t.Parallel()
	const (
		obs   = `C:\p6live\observer.exe`
		sidA  = "S-1-15-2-377672063-2526458857"
		sidB  = "S-1-15-2-1646696914-3659874966"
		other = `C:\Windows\System32\conhost.exe`
	)
	isObs := func(p string) bool { return strings.EqualFold(p, obs) }
	root := BoxProcess{PID: 100, Created: 1000, Image: `C:\p6live\mxc\wxc-exec.exe`}
	box := BoxProcess{PID: 200, ParentPID: 100, Created: 1001, Image: obs, AppContainerSID: sidA}
	cases := []struct {
		name  string
		procs []BoxProcess
		want  string
		err   error
	}{
		{"nothing yet", nil, "", ErrBoxNotStarted},
		{"the box process", []BoxProcess{box}, sidA, nil},
		{"under a helper of wxc-exec", []BoxProcess{{PID: 150, ParentPID: 100, Created: 1000, Image: other}, {PID: 201, ParentPID: 150, Created: 1002, Image: obs, AppContainerSID: sidA}}, sidA, nil},
		{"its children in the same container", []BoxProcess{box, {PID: 300, ParentPID: 200, Created: 1005, Image: obs, AppContainerSID: strings.ToLower(sidA)}}, sidA, nil},
		{"another image in a container", []BoxProcess{{PID: 210, ParentPID: 100, Created: 1001, Image: other, AppContainerSID: sidB}}, "", ErrBoxNotStarted},
		{"the inner image outside any container", []BoxProcess{{PID: 210, ParentPID: 100, Created: 1001, Image: obs}}, "", ErrBoxNotStarted},
		{"an unreadable image", []BoxProcess{{PID: 210, ParentPID: 100, Created: 1001, AppContainerSID: sidB}}, "", ErrBoxNotStarted},
		{"a reused parent PID (older than wxc-exec)", []BoxProcess{{PID: 220, ParentPID: 100, Created: 900, Image: obs, AppContainerSID: sidB}}, "", ErrBoxNotStarted},
		{"a grandchild under a reused PID", []BoxProcess{{PID: 150, ParentPID: 100, Created: 1001, Image: other}, {PID: 230, ParentPID: 150, Created: 999, Image: obs, AppContainerSID: sidB}}, "", ErrBoxNotStarted},
		{"an unrelated process", []BoxProcess{{PID: 240, ParentPID: 7, Created: 2000, Image: obs, AppContainerSID: sidB}}, "", ErrBoxNotStarted},
		{"two containers", []BoxProcess{box, {PID: 250, ParentPID: 100, Created: 1003, Image: obs, AppContainerSID: sidB}}, "", ErrBoxAmbiguous},
		{"a cycle", []BoxProcess{{PID: 260, ParentPID: 261, Created: 1001, Image: obs, AppContainerSID: sidB}, {PID: 261, ParentPID: 260, Created: 1001, Image: obs, AppContainerSID: sidB}}, "", ErrBoxNotStarted},
		{"root listed again", []BoxProcess{root, box}, sidA, nil},
	}
	for _, c := range cases {
		got, err := BoxSID(root, c.procs, isObs)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
	}
	if _, err := BoxSID(root, []BoxProcess{{PID: 210, ParentPID: 100, Created: 1001, Image: other, AppContainerSID: sidB}}, isObs); err == nil || !strings.Contains(err.Error(), "1 processes under it") || !strings.Contains(err.Error(), "conhost.exe") {
		t.Fatalf("a not-yet answer says what the walk met: %v", err)
	}
	if _, err := BoxSID(root, []BoxProcess{box}, nil); err == nil {
		t.Fatal("no image check")
	}
	if _, err := BoxSID(root, []BoxProcess{box, {PID: 250, ParentPID: 100, Created: 1003, Image: obs, AppContainerSID: sidB}}, isObs); err == nil || !strings.Contains(err.Error(), sidA) || !strings.Contains(err.Error(), sidB) {
		t.Fatalf("an ambiguous answer names both SIDs: %v", err)
	}
}

// TestPortIdentityStream: the identity answer is read with GET and the
// run's token on every tier.
func TestPortIdentityStream(t *testing.T) {
	t.Parallel()
	tok := token(t)
	other, _ := EncodeToken([]byte(strings.Repeat("z", 32)))
	for _, tier := range Tiers() {
		if r := Classify(Request{Method: "GET", RequestURI: "/identity/" + tok}, tok, tier); r.Refused() || r.Stream != StreamIdentity {
			t.Errorf("%s: %+v", tier, r)
		}
	}
	for name, c := range map[string]struct {
		req    Request
		status int
	}{
		"another token": {Request{Method: "GET", RequestURI: "/identity/" + other}, 403},
		"no token":      {Request{Method: "GET", RequestURI: "/identity/"}, 403},
		"by POST":       {Request{Method: "POST", RequestURI: "/identity/" + tok}, 400},
	} {
		if r := Classify(c.req, tok, vocab.TierInternet); r.Status != c.status {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := Classify(Request{Method: "GET", RequestURI: "/identity/" + tok}, tok, vocab.TierHost); !r.Refused() {
		t.Fatal("the host tier opened the identity stream")
	}
}
