//go:build windows

package attachsock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// transport_windows_test.go pins the Windows named-pipe transport's SECURITY
// and GUARD properties on a real pipe (audit DI-09 full). These are the
// properties that justify serving the attach channel — which carries the
// writer lease and, when [terminal.attach].forward_auth_env is on, forwarded
// provider credentials — on a native-Windows daemon at all, so they are pinned
// against the object the OS actually created, never against the SDDL string we
// asked for.

// testPipeEndpoint returns a unique pipe endpoint for one test, derived the
// same way production is (hash of a DB path) so the naming under test is the
// shipped naming.
func testPipeEndpoint(t *testing.T) string {
	t.Helper()
	ep, err := Endpoint(filepath.Join(t.TempDir(), "observer.db"))
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	return ep
}

// pipeSecurityDescriptor reads the security descriptor of a live pipe by name.
// A pipe with no instance in the LISTENING state answers the CreateFile that
// GetNamedSecurityInfo performs with ERROR_PIPE_BUSY, so the caller must have
// an accept loop running; we retry briefly to absorb the arming race.
func pipeSecurityDescriptor(t *testing.T, endpoint string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	var lastErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sd, err := windows.GetNamedSecurityInfo(
			endpoint,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
		)
		if err == nil {
			return sd
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("GetNamedSecurityInfo(%q): %v", endpoint, lastErr)
	return nil
}

// currentUserSIDString returns the calling process's user SID, the SID the
// pipe DACL must name.
func currentUserSIDString(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return user.User.Sid.String()
}

// TestPipeDACLIsOwnerOnly pins the shipped security model: the attach pipe's
// DACL is PROTECTED (nothing inherited from the pipe namespace) and grants
// access to exactly two principals — the calling user and SYSTEM — with a
// leading DENY for the NETWORK group that closes a pipe's SMB reachability
// (\\host\pipe\…), the one way a pipe would otherwise be weaker than the
// AF_UNIX socket it replaces. No Everyone / Authenticated Users / Users ACE
// may appear.
func TestPipeDACLIsOwnerOnly(t *testing.T) {
	endpoint := testPipeEndpoint(t)
	ln, err := ListenSocket(endpoint)
	if err != nil {
		t.Fatalf("ListenSocket(%q): %v", endpoint, err)
	}
	defer func() { _ = ln.Close() }()
	// Keep an instance armed so the security read can open the pipe.
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	sd := pipeSecurityDescriptor(t, endpoint)
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("SD control: %v", err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL is not protected (control %#x) — it could inherit a looser ACE", ctrl)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("SD DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("pipe has a NULL DACL — that grants everyone full access")
	}

	userSID := currentUserSIDString(t)
	const (
		sidNetwork = "S-1-5-2"
		sidSystem  = "S-1-5-18"
	)
	// Every SID that must never appear on this object.
	forbidden := map[string]string{
		"S-1-1-0":      "Everyone",
		"S-1-5-11":     "Authenticated Users",
		"S-1-5-32-545": "BUILTIN\\Users",
		"S-1-5-32-544": "BUILTIN\\Administrators",
		"S-1-5-7":      "Anonymous",
		"S-1-5-4":      "Interactive",
	}

	type ace struct {
		typ  uint8
		mask windows.ACCESS_MASK
		sid  string
	}
	var aces []ace
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &a); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart)).String()
		aces = append(aces, ace{typ: a.Header.AceType, mask: a.Mask, sid: sid})
	}

	if len(aces) != 3 {
		t.Fatalf("DACL has %d ACEs (%+v), want exactly 3: deny NETWORK, allow user, allow SYSTEM", len(aces), aces)
	}
	// Canonical order: the deny ACE leads.
	if aces[0].typ != windows.ACCESS_DENIED_ACE_TYPE || aces[0].sid != sidNetwork {
		t.Fatalf("ACE 0 = %+v, want a DENY for NETWORK (%s)", aces[0], sidNetwork)
	}
	var allowedUser, allowedSystem bool
	for _, a := range aces[1:] {
		if a.typ != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("ACE %+v is not an allow ACE", a)
		}
		switch a.sid {
		case userSID:
			allowedUser = true
		case sidSystem:
			allowedSystem = true
		default:
			t.Fatalf("unexpected allow ACE for SID %s (only the owner %s and SYSTEM %s may appear)", a.sid, userSID, sidSystem)
		}
	}
	if !allowedUser {
		t.Fatalf("no allow ACE for the calling user %s — the owner cannot use its own attach channel", userSID)
	}
	if !allowedSystem {
		t.Fatalf("no allow ACE for SYSTEM (%s)", sidSystem)
	}
	for _, a := range aces {
		if name, bad := forbidden[a.sid]; bad && a.typ == windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("DACL grants access to %s (%s) — the attach channel must be owner-only", name, a.sid)
		}
	}
}

// TestListenPipeRefusesExistingName pins the live-daemon guard: creating the
// attach pipe uses FILE_FLAG_FIRST_PIPE_INSTANCE, so a SECOND daemon on the
// same DB cannot create — let alone steal — the endpoint. It must surface as
// ErrSocketLiveDaemon with copy that names the cause, and the FIRST listener
// must remain usable. Once the first listener closes, the name is free again
// (a crashed daemon leaves no stale object to reclaim, unlike a unix socket).
func TestListenPipeRefusesExistingName(t *testing.T) {
	endpoint := testPipeEndpoint(t)
	ln1, err := ListenSocket(endpoint)
	if err != nil {
		t.Fatalf("first ListenSocket: %v", err)
	}
	go func() {
		for {
			c, aerr := ln1.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, err = ListenSocket(endpoint)
	if !errors.Is(err, ErrSocketLiveDaemon) {
		t.Fatalf("second ListenSocket err = %v, want ErrSocketLiveDaemon", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "another observer daemon is serving the attach channel for this DB") {
		t.Fatalf("second ListenSocket message = %q, want it to name the live daemon", msg)
	}

	// The incumbent is untouched: it still answers a dial.
	c, derr := Dial(endpoint)
	if derr != nil {
		t.Fatalf("incumbent listener stopped answering after the refused second listen: %v", derr)
	}
	_ = c.Close()

	// Closing the incumbent frees the name — the pipe object dies with its
	// last handle, so a restart binds cleanly with no unlink step.
	_ = ln1.Close()
	ln2, rerr := ListenSocket(endpoint)
	if rerr != nil {
		t.Fatalf("rebind after the incumbent closed: %v", rerr)
	}
	_ = ln2.Close()
}

// TestPipeDialRoundTrip runs the REAL protocol over a real pipe: Serve on one
// side, Dial + Attach on the other, one output frame across and an exit frame
// back. This is the end-to-end proof that the framing above the transport is
// transport-agnostic — the same harness the AF_UNIX test uses, over a pipe.
func TestPipeDialRoundTrip(t *testing.T) {
	endpoint := testPipeEndpoint(t)
	ln, err := ListenSocket(endpoint)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	sess := newFakeSession("H", "R")
	host := newFakeHost(sess)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- Serve(ctx, ln, host, nil) }()

	conn, err := Dial(endpoint)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	out := &syncBuffer{}
	resultCh := make(chan ExitStatus, 1)
	go func() {
		st, _ := Attach(context.Background(), conn, SpawnRequest{Tool: "t", Subcommand: "s"}, ClientIO{Stdout: out})
		resultCh <- st
	}()
	select {
	case <-host.gotReq:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not complete over the named pipe")
	}
	sess.feed([]byte("ok"))
	waitFor(t, "stdout ok", func() bool { return out.String() == "ok" })
	sess.endOutput(0)
	select {
	case st := <-resultCh:
		if !st.Exited || st.Code != 0 {
			t.Fatalf("status = %+v, want a clean child exit", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Attach did not return")
	}

	cancel()
	select {
	case serr := <-serveDone:
		if serr != nil {
			t.Fatalf("Serve returned %v, want nil on ctx cancel", serr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

// TestPipeNameExistsEnumerates pins the helper that disambiguates the
// live-daemon ERROR_ACCESS_DENIED: it must see a pipe that exists, not see one
// that does not, and answer without connecting (it enumerates the namespace).
func TestPipeNameExistsEnumerates(t *testing.T) {
	endpoint := testPipeEndpoint(t)
	if pipeNameExists(endpoint) {
		t.Fatalf("pipeNameExists(%q) = true before anything created it", endpoint)
	}
	ln, err := ListenSocket(endpoint)
	if err != nil {
		t.Fatalf("ListenSocket: %v", err)
	}
	if !pipeNameExists(endpoint) {
		t.Fatalf("pipeNameExists(%q) = false while a listener holds it", endpoint)
	}
	_ = ln.Close()
	if pipeNameExists(endpoint) {
		t.Fatalf("pipeNameExists(%q) = true after the listener closed", endpoint)
	}
	// A non-pipe path is never mistaken for a pipe name.
	if pipeNameExists(filepath.Join(os.TempDir(), "not-a-pipe")) {
		t.Fatal("pipeNameExists accepted a filesystem path")
	}
}
