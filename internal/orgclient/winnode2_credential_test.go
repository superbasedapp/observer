package orgclient

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// enrolOverSSH is a Windows-shaped enrolment from a process with no logon
// session: Credential Manager answers ERROR_NO_SUCH_LOGON_SESSION, so the
// bearer and the agent key land in the 0600 file store. An older build also
// left its marker there, which the test plants.
func enrolOverSSH(t *testing.T, service, dir string) {
	t.Helper()
	keyring.MockInitWithError(errNoSuchLogonSession)
	fs := OpenBearerStore(service, dir, quietLogger())
	if fs.Backend() != "file" {
		t.Fatalf("precondition: Backend() = %q, want file", fs.Backend())
	}
	if err := fs.SaveBearer("file-bearer"); err != nil {
		t.Fatal(err)
	}
	if err := fs.SaveAgentKey(winnode2Key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "org-bearer", legacyKeychainMarker), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
}

var winnode2Key = func() []byte {
	k := make([]byte, 64)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}()

func fileRecordExists(dir, service, rec string) bool {
	_, err := os.Stat(filepath.Join(dir, "org-bearer", service+"."+rec))
	return err == nil
}

// TestReadOnlyOpenCreatesNoCredentialMarker (WINNODE2 16c and 16d): opening
// the store and reading it, as `observer org status` or `observer doctor`
// does, writes nothing under org-bearer/, and the downgrade warning prints
// once per install, not once per process.
func TestReadOnlyOpenCreatesNoCredentialMarker(t *testing.T) {
	keyring.MockInitWithError(errNoSuchLogonSession)
	dir := t.TempDir()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	for i := 0; i < 3; i++ { // three CLI processes
		bs := OpenBearerStore("sbo-readonly", dir, logger)
		if _, err := bs.LoadBearer(); !errors.Is(err, ErrNoSecret) {
			t.Fatalf("LoadBearer: %v", err)
		}
		_ = bs.Backend()
	}
	if _, err := os.Stat(filepath.Join(dir, "org-bearer")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a read-only open created the credential store directory: %v", err)
	}
	if n := strings.Count(logs.String(), "OS keychain unavailable"); n != 1 {
		t.Fatalf("warned %d times, want once per install:\n%s", n, logs.String())
	}
	if _, err := os.Stat(noticePath(dir, bearerNoticeKey("sbo-readonly"))); err != nil {
		t.Fatalf("the notice marker is missing: %v", err)
	}
}

// TestMachineKeyWarningOncePerInstall (WINNODE2 16c): two CLI processes on
// one install warn once for one reason; a new reason warns again.
func TestMachineKeyWarningOncePerInstall(t *testing.T) {
	dir := t.TempDir()
	var logs bytes.Buffer
	for i := 0; i < 2; i++ {
		c := newTestClient(t, newAgentStore(t), &memBearerStore{bearer: "b"})
		c.logger = slog.New(slog.NewTextHandler(&logs, nil))
		c.SetNoticeDir(dir)
		c.noteMachineProof(MachineProofState{Known: true, Reason: "no Windows logon session"})
	}
	if n := strings.Count(logs.String(), "org machine key unavailable;"); n != 1 {
		t.Fatalf("warned %d times, want once:\n%s", n, logs.String())
	}
	c := newTestClient(t, newAgentStore(t), &memBearerStore{bearer: "b"})
	c.logger = slog.New(slog.NewTextHandler(&logs, nil))
	c.SetNoticeDir(dir)
	c.noteMachineProof(MachineProofState{Known: true, Reason: "the OS credential store refused the machine key: x"})
	if n := strings.Count(logs.String(), "org machine key unavailable;"); n != 2 {
		t.Fatalf("a new reason did not warn again (%d warnings)", n)
	}
}

// TestPushCycleReportsCredentialView (WINNODE2 item 1b(b)): a push cycle in
// a process that cannot read the bearer reports "not enrolled" with the
// reason to the sink, once per change.
func TestPushCycleReportsCredentialView(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	if err := s.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "http://127.0.0.1:1",
		UserID: "u1", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatal(err)
	}
	bs := &memBearerStore{}
	c := newTestClient(t, s, bs)
	var seen []CredentialState
	c.SetCredentialSink(func(v CredentialState) { seen = append(seen, v) })
	for i := 0; i < 2; i++ {
		if _, err := c.PushOnce(ctx); !errors.Is(err, ErrNotEnrolled) {
			t.Fatalf("PushOnce: %v", err)
		}
	}
	if len(seen) != 1 || seen[0].Enrolled || seen[0].Reason != credentialNoBearer {
		t.Fatalf("sink saw %+v, want one not-enrolled view naming the bearer", seen)
	}
	bs.bearer, bs.key = "b", newTestKey(t)
	_, _ = c.PushOnce(ctx)
	if len(seen) != 2 || !seen[1].Enrolled || !c.Credential().Enrolled {
		t.Fatalf("after the credential appeared: %+v", seen)
	}
}
