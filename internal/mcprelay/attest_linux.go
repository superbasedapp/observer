//go:build linux

package mcprelay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcAttestor verifies the parent through procfs: /proc/<ppid>/exe is the
// kernel's magic link to the RUNNING image (a replaced or deleted binary on
// disk does not change it; a symlinked launcher path is resolved by the
// kernel), its bytes are hashed through that link, and the parent's pid +
// start time (field 22 of /proc/<ppid>/stat) are read BEFORE and AFTER so a
// pid recycled mid-check is detected. Any discrepancy downgrades.
type ProcAttestor struct {
	// Root is the procfs root ("/proc" when empty; tests point it at a
	// synthetic tree).
	Root string
	// PPID overrides os.Getppid (tests).
	PPID int
	// afterHash runs between the image hash and the re-read (tests inject
	// a pid-reuse race here).
	afterHash func()
}

func defaultAttestor() Attestor { return ProcAttestor{} }

// Attest implements Attestor.
func (a ProcAttestor) Attest(reg ClientRegistry) ParentIdentity {
	root := a.Root
	if root == "" {
		root = "/proc"
	}
	ppid := a.PPID
	if ppid == 0 {
		ppid = os.Getppid()
	}
	if ppid <= 1 {
		return configured(ppid, "parent is init/unknown")
	}
	if reg == nil {
		return configured(ppid, "no registered-client list")
	}
	dir := filepath.Join(root, strconv.Itoa(ppid))
	start1, err := procStartTime(dir)
	if err != nil {
		return configured(ppid, "parent start time: "+err.Error())
	}
	exe, err := os.Readlink(filepath.Join(dir, "exe"))
	if err != nil {
		return configured(ppid, "parent exe: "+err.Error())
	}
	if strings.HasSuffix(exe, " (deleted)") {
		return configured(ppid, "parent image was deleted/replaced on disk")
	}
	f, err := os.Open(filepath.Join(dir, "exe"))
	if err != nil {
		return configured(ppid, "open parent image: "+err.Error())
	}
	h := sha256.New()
	_, herr := io.Copy(h, f)
	_ = f.Close()
	if herr != nil {
		return configured(ppid, "hash parent image: "+herr.Error())
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if a.afterHash != nil {
		a.afterHash()
	}
	// Re-read: the pid must still be the same process (start time equal)
	// and still our parent.
	start2, err := procStartTime(dir)
	if err != nil || start1 != start2 {
		return configured(ppid, "parent pid changed during attestation (pid reuse)")
	}
	if a.PPID == 0 && os.Getppid() != ppid {
		return configured(ppid, "parent changed during attestation")
	}
	agent, product, ok := reg.Match(exe, sum)
	if !ok {
		return ParentIdentity{PID: ppid, Exe: exe, SHA256: sum, Attestation: "configured", Reason: "parent image is not a registered client"}
	}
	return ParentIdentity{PID: ppid, Exe: exe, SHA256: sum, Agent: agent, Product: product, Attestation: "process_attested", Reason: "verified parent image"}
}

// procStartTime reads field 22 (starttime) of /proc/<pid>/stat. The comm
// field may contain spaces/parens, so fields are counted after the last ')'.
func procStartTime(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return "", err
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return "", fmt.Errorf("malformed stat")
	}
	fields := strings.Fields(s[i+1:])
	// fields[0] is state (field 3); starttime is field 22 -> index 19.
	if len(fields) < 20 {
		return "", fmt.Errorf("short stat")
	}
	return fields[19], nil
}
