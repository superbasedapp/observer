//go:build windows && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestMXCHostRunBoxIsOwnedByTheTokenUser (B2): the run's box folder, its
// temp and LOCALAPPDATA folders, the inner log and the loopback record go
// through the ownership helper, and each one on disk is owned by the token
// user with a DACL that lets no one but that user, SYSTEM and the
// Administrators group write (the launch record is sandboxrelayd's own,
// pinned there). An elevated live run (WIN-7) left the first four owned by
// BUILTIN\Administrators.
func TestMXCHostRunBoxIsOwnedByTheTokenUser(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	claimed := recordOwnerClaims(t)
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-box-own1"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := newMXCHostRun(mxcPlanFile{RunID: rec.RunID}, rec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	want := []string{r.boxDir, r.tmpDir, mxcInnerLogPath(r.tmpDir), mxcLocalAppDataDir(r.boxDir), filepath.Join(r.boxDir, mxcLoopbackName)}
	if !slices.Equal(*claimed, want) {
		t.Fatalf("claimed %q, want %q", *claimed, want)
	}
	for _, p := range append(want, filepath.Join(r.boxDir, sandboxrelayd.BoxRecordName)) {
		assertTokenUserPrivate(t, p)
	}
}

// assertTokenUserPrivate checks p's owner is this process's token user and
// that its DACL grants write access to no one but that user, SYSTEM, the
// Administrators group and CREATOR OWNER (the relay reader's rule).
func assertTokenUserPrivate(t *testing.T, p string) {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := tu.User.Sid
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(me) {
		t.Fatalf("%s is owned by %v, want the token user %s", p, owner, me)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no DACL (%v)", p, err)
	}
	trusted := []*windows.SID{me}
	for _, w := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid, windows.WinCreatorOwnerSid} {
		if s, err := windows.CreateWellKnownSid(w); err == nil {
			trusted = append(trusted, s)
		}
	}
	const write = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL | 0x40
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&write == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !slices.ContainsFunc(trusted, sid.Equals) {
			t.Fatalf("%s: its DACL lets %s write", p, sid)
		}
	}
	if _, err := os.Lstat(p); err != nil {
		t.Fatal(err)
	}
}
