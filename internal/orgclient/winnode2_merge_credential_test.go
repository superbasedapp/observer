package orgclient

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// The WINNODE2 merge ruling on issue 1b (H1 of the audit): a file-stored
// credential stays where the enrolment put it. A desktop daemon reads it
// through the keychain store's file fallback; a process with no Windows
// logon session (a session 0 or WMI daemon, an SSH CLI) keeps reading the
// file. Nothing copies the credential into the keychain or deletes the
// files. To keep the two stores from diverging, a keychain save also
// overwrites a file copy that already exists, and never creates one.

// openNoLogonSession is a process with no Windows logon session: Credential
// Manager answers ERROR_NO_SUCH_LOGON_SESSION, so the store is the file one.
func openNoLogonSession(t *testing.T, service, dir string) BearerStore {
	t.Helper()
	keyring.MockInitWithError(errNoSuchLogonSession)
	bs := OpenBearerStore(service, dir, quietLogger())
	if bs.Backend() != "file" {
		t.Fatalf("precondition: Backend() = %q, want file", bs.Backend())
	}
	return bs
}

// openDesktop is a process in the developer's desktop sign-in: Credential
// Manager works (an empty test keychain).
func openDesktop(t *testing.T, service, dir string) BearerStore {
	t.Helper()
	keyring.MockInit()
	bs := OpenBearerStore(service, dir, quietLogger())
	if bs.Backend() != "keychain" {
		t.Fatalf("precondition: Backend() = %q, want keychain", bs.Backend())
	}
	return bs
}

func readCredential(t *testing.T, label string, bs BearerStore) (string, ed25519.PrivateKey) {
	t.Helper()
	b, err := bs.LoadBearer()
	if err != nil {
		t.Fatalf("%s: LoadBearer: %v", label, err)
	}
	k, err := bs.LoadAgentKey()
	if err != nil {
		t.Fatalf("%s: LoadAgentKey: %v", label, err)
	}
	return b, k
}

// TestSSHEnrolmentReadsTheSameCredentialEverywhere: an SSH-shaped enrolment,
// then a desktop daemon, then a no-logon-session process all read the same
// credential, and the file copies are still there at the end.
func TestSSHEnrolmentReadsTheSameCredentialEverywhere(t *testing.T) {
	dir, service := t.TempDir(), "sbo-h1-everywhere"
	enrolOverSSH(t, service, dir)

	daemon := openDesktop(t, service, dir)
	b, k := readCredential(t, "desktop daemon", daemon)
	if b != "file-bearer" || !bytes.Equal(k, winnode2Key) {
		t.Fatalf("desktop daemon read %q and another key", b)
	}

	headless := openNoLogonSession(t, service, dir)
	b, k = readCredential(t, "no-logon-session process", headless)
	if b != "file-bearer" || !bytes.Equal(k, winnode2Key) {
		t.Fatalf("no-logon-session process read %q and another key", b)
	}
	for _, rec := range []string{recBearer, recAgentKey} {
		if !fileRecordExists(dir, service, rec) {
			t.Fatalf("the file copy of %s is gone", rec)
		}
	}
}

// TestDesktopReEnrolmentUpdatesTheFileCopy: a re-enrolment from the desktop
// writes the keychain and overwrites the file copies an SSH enrolment left,
// so a no-logon-session process reads the new credential, not the old one.
func TestDesktopReEnrolmentUpdatesTheFileCopy(t *testing.T) {
	dir, service := t.TempDir(), "sbo-h1-reenrol"
	enrolOverSSH(t, service, dir)
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

	desktop := openDesktop(t, service, dir)
	if err := desktop.SaveBearer("desktop-bearer"); err != nil {
		t.Fatal(err)
	}
	if err := desktop.SaveAgentKey(newKey); err != nil {
		t.Fatal(err)
	}
	b, k := readCredential(t, "desktop", desktop)
	if b != "desktop-bearer" || !bytes.Equal(k, newKey) {
		t.Fatalf("desktop read %q and another key", b)
	}

	headless := openNoLogonSession(t, service, dir)
	b, k = readCredential(t, "no-logon-session process", headless)
	if b != "desktop-bearer" || !bytes.Equal(k, newKey) {
		t.Fatalf("no-logon-session process read %q (old file copy?), want the re-enrolment's credential", b)
	}
}

// TestDesktopEnrolmentCreatesNoFileCopy: an enrolment with a working
// keychain and no file copy writes nothing under org-bearer/.
func TestDesktopEnrolmentCreatesNoFileCopy(t *testing.T) {
	dir, service := t.TempDir(), "sbo-h1-nofile"
	desktop := openDesktop(t, service, dir)
	if err := desktop.SaveBearer("desktop-bearer"); err != nil {
		t.Fatal(err)
	}
	if err := desktop.SaveAgentKey(winnode2Key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "org-bearer")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a keychain enrolment created the file store: %v", err)
	}
	b, _ := readCredential(t, "desktop", desktop)
	if b != "desktop-bearer" {
		t.Fatalf("desktop read %q", b)
	}
}
