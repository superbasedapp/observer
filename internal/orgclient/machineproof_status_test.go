package orgclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestMachineProofUnavailableReason pins the classifier rows: the Windows
// "no logon session" errno, wrapped as the store wraps it, is named as such;
// anything else carries the error.
func TestMachineProofUnavailableReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("orgclient: store machine key: %w", errNoSuchLogonSession), "no Windows logon session"},
		{errNoSuchLogonSession, "no Windows logon session"},
		{errors.New("dbus: no secret service"), "the OS credential store refused the machine key: dbus: no secret service"},
	}
	for _, tc := range cases {
		if got := MachineProofUnavailableReason(tc.err); !strings.HasPrefix(got, tc.want) {
			t.Errorf("reason(%v) = %q, want prefix %q", tc.err, got, tc.want)
		}
	}
}

// noSessionKeys is a machine key slot in a process with no Windows logon
// session: the read finds nothing and the write is refused with 1312.
type noSessionKeys struct{ fail bool }

func (k *noSessionKeys) LoadMachineKey() ([]byte, error) {
	if k.fail {
		return nil, errNoSuchLogonSession
	}
	return nil, ErrNoSecret
}

func (k *noSessionKeys) SaveMachineKey([]byte) error {
	if k.fail {
		return errNoSuchLogonSession
	}
	return nil
}

// TestMachineProofAbsenceIsLoudOnce: a node with no logon session warns once
// per process naming the reason (it used to warn on every request with only
// the raw error), the sink sees each change once, and a recovered key is
// reported available again.
func TestMachineProofAbsenceIsLoudOnce(t *testing.T) {
	var logs bytes.Buffer
	c := newTestClient(t, newAgentStore(t), &memBearerStore{bearer: "b"})
	c.logger = slog.New(slog.NewTextHandler(&logs, nil))
	keys := &noSessionKeys{fail: true}
	c.SetMachineKeyStore(keys)
	var seen []MachineProofState
	c.SetMachineProofSink(func(p MachineProofState) { seen = append(seen, p) })
	enr := &store.Enrolment{OrgID: "org-1", UserID: "u1", OrgServerURL: "http://127.0.0.1:1", EnrolledAt: time.Now().UTC().Format(time.RFC3339)}

	if got := c.ProbeMachineProof(); got.Available || !strings.HasPrefix(got.Reason, "no Windows logon session") {
		t.Fatalf("probe = %+v, want unavailable: no Windows logon session", got)
	}
	for i := 0; i < 3; i++ {
		req, _ := newProofRequest(t)
		c.attachMachineProof(context.Background(), req, enr, "machine-1", "GET", "/api/agent/budget")
		if req.Header.Get("X-SBO-Machine-Signature") != "" {
			t.Fatal("a request signed without a machine key")
		}
	}
	if n := strings.Count(logs.String(), "org machine key unavailable"); n != 1 {
		t.Fatalf("warned %d times, want once:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "no Windows logon session") {
		t.Fatalf("the warning does not name the reason:\n%s", logs.String())
	}
	if len(seen) != 1 || seen[0].Available || c.MachineProof().Available {
		t.Fatalf("sink saw %+v, want one unavailable change", seen)
	}

	keys.fail = false
	req, _ := newProofRequest(t)
	c.attachMachineProof(context.Background(), req, enr, "machine-1", "GET", "/api/agent/budget")
	if len(seen) != 2 || !seen[1].Available || req.Header.Get("X-SBO-Machine-Signature") == "" {
		t.Fatalf("after recovery: sink %+v, signed=%v", seen, req.Header.Get("X-SBO-Machine-Signature") != "")
	}
}

func newProofRequest(t *testing.T) (*http.Request, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/api/agent/budget", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req, nil
}
