//go:build windows

package sandboxrelayd

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestElevatedOwnerDescriptor pins the reader rule an elevated daemon's
// records meet (lane SBX-UPD, P6 leftover): a descriptor owned by
// BUILTIN\Administrators (an elevated token's default owner) is refused,
// the same DACL owned by the token user passes.
func TestElevatedOwnerDescriptor(t *testing.T) {
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	const dacl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)"
	admins, err := windows.SecurityDescriptorFromString("O:BA" + sprintfDACL(dacl, me))
	if err != nil {
		t.Fatal(err)
	}
	mine, err := windows.SecurityDescriptorFromString("O:" + me.String() + sprintfDACL(dacl, me))
	if err != nil {
		t.Fatal(err)
	}
	if privateDescriptor(admins) {
		t.Fatal("a record owned by Administrators passed the reader rule")
	}
	if !privateDescriptor(mine) {
		t.Fatal("the same record owned by the token user was refused")
	}
}

// TestElevatedClaimSetsTheOwnerExplicitly (B2): with an elevated token the
// helper writes the owner, the token user, on every object it is handed,
// and the object then passes the reader rule (owner and DACL). Elevation
// itself cannot be produced in a test, so the elevation read is forced; the
// owner write is the real SetNamedSecurityInfo, wrapped to be seen.
func TestElevatedClaimSetsTheOwnerExplicitly(t *testing.T) {
	me, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	savedElev, savedSet := tokenIsElevated, setOwner
	t.Cleanup(func() { tokenIsElevated, setOwner = savedElev, savedSet })
	var set []string
	tokenIsElevated = func() bool { return true }
	setOwner = func(path string, owner *windows.SID) error {
		if !owner.Equals(me) {
			t.Errorf("owner for %s is %s, want the token user %s", path, owner, me)
		}
		set = append(set, path)
		return savedSet(path, owner)
	}
	dir := t.TempDir() + `\rec-dir`
	if err := MkdirAllOwned(dir); err != nil {
		t.Fatal(err)
	}
	file := dir + `\rec.json`
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := OwnRecord(file); err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 || set[0] != dir || set[1] != file {
		t.Fatalf("owner set on %q, want [%s %s]", set, dir, file)
	}
	for _, p := range []string{dir, file} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if !privateDescriptor(sd) {
			t.Fatalf("%s fails the owner and DACL rule after the claim: %s", p, sd)
		}
	}
	// Not elevated: nothing is written (the object is already its creator's).
	set = nil
	tokenIsElevated = func() bool { return false }
	if err := OwnRecord(file); err != nil || len(set) != 0 {
		t.Fatalf("a token that is not elevated wrote an owner: %q, %v", set, err)
	}
}

// TestRecordRoundTripOwned: a run record and a box record written by this
// process read back (the owner is the token user whether or not the token
// is elevated).
func TestRecordRoundTripOwned(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRunRecord(RunRecord{RunID: "run-roundtrip1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRun(dir, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRun(dir, rec.RunID); err != nil {
		t.Fatalf("ReadRun: %v", err)
	}
	sock := t.TempDir()
	if err := WriteBoxRecord(sock, rec); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadBoxRecord(sock + `\` + BoxRecordName); err != nil || !ok {
		t.Fatalf("ReadBoxRecord: ok=%v err=%v", ok, err)
	}
}

func sprintfDACL(format string, me *windows.SID) string {
	return strings.ReplaceAll(format, "%s", me.String())
}
