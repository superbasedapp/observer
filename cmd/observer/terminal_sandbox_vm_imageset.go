//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// terminal_sandbox_vm_imageset.go loads the verified guest image set for the
// probe and the run (lane SBX-P4 decision 2): the two signed kinds
// sandbox.rootfs and sandbox.guest_binary from the node's sandbox content
// store, every bulk entry re-hashed from a no-follow descriptor on every
// load, streamed (a rootfs is gigabytes), never held in memory, and the
// whole set judged by sandboximage.ResolveVMSet. The host's running binary
// is never substituted for the guest observer.

// vmImageSet is one resolved set: the verdict and, when it may boot, the
// paths of its entries in the store.
type vmImageSet struct {
	res   sandboximage.VMSetResult
	paths map[string]string
	// guest is the guest observer's path and entry.
	guest      string
	guestEntry content.Entry
	// debugSigned: both kinds verified only under the imported debug key.
	debugSigned bool
}

// vmOpenNoFollow opens a store file without following a symlink (a
// variable so a test on another OS can stand it in).
var vmOpenNoFollow = openNoFollow

// vmRehash streams path through sha256 under the entry's size and compares.
func vmRehash(path string, e content.Entry) error {
	f, err := vmOpenNoFollow(path)
	if err != nil {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " cannot be opened without following a link: " + err.Error()}
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != e.SizeBytes {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " is not a regular file of the listed size"}
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, e.SizeBytes+1)); err != nil {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " cannot be read"}
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(e.SHA256) {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " does not match its digest"}
	}
	return nil
}

// loadVMImageSet loads and judges the set in store.
func loadVMImageSet(store contentchan.Store, tr contentchan.Trust, want, agentVersion string) vmImageSet {
	goarch := store.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	in := sandboximage.VMSetInput{Arch: goarch, AgentVersion: agentVersion, Want: want, BulkErr: map[string]error{}}
	out := vmImageSet{paths: map[string]string{}}
	kind := func(k content.Kind, tr contentchan.Trust) (contentchan.Loaded, sandboximage.KindLoad) {
		l, err := store.Load(k, tr, 0)
		if errors.Is(err, contentchan.ErrNotInstalled) {
			return l, sandboximage.KindLoad{NotInstalled: true}
		}
		if err != nil {
			return l, sandboximage.KindLoad{LoadErr: err}
		}
		return l, sandboximage.KindLoad{Manifest: l.Manifest, Freshness: l.Freshness}
	}
	rl, rk := kind(content.SandboxRootfs, tr)
	gl, gk := kind(content.SandboxGuest, tr)
	// A debug image set (R-016) verifies only under the debug key it was
	// imported with, never beside the vendor keys: both kinds must verify
	// under it alone, and the resolution then requires a debug descriptor.
	if dk := vmDebugKey(store); dk != nil && (rk.LoadErr != nil || gk.LoadErr != nil) {
		dtr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{dk}}
		drl, drk := kind(content.SandboxRootfs, dtr)
		dgl, dgk := kind(content.SandboxGuest, dtr)
		if drk.LoadErr == nil && dgk.LoadErr == nil && !drk.NotInstalled && !dgk.NotInstalled {
			rl, rk, gl, gk = drl, drk, dgl, dgk
			in.DebugSigned = true
		}
	}
	in.Rootfs, in.Guest = rk, gk
	if !rk.NotInstalled && rk.LoadErr == nil {
		in.Descriptor, in.DescriptorErr = rl.ReadArtifact(sandboximage.VMDescriptorName)
		in.SBOM, in.SBOMErr = rl.ReadArtifact(sandboximage.VMSBOMName)
		for _, n := range sandboximage.BulkEntries() {
			p, e, err := rl.ArtifactPath(n)
			if err == nil {
				err = vmRehash(p, e)
			}
			in.BulkErr[n] = err
			out.paths[n] = p
		}
	}
	if !gk.NotInstalled && gk.LoadErr == nil {
		p, e, err := gl.ArtifactPath(sandboximage.GuestBinaryName)
		if err == nil {
			err = vmRehash(p, e)
		}
		in.GuestEntry, in.GuestErr = e, err
		out.guest, out.guestEntry = p, e
	}
	out.res = sandboximage.ResolveVMSet(in)
	out.debugSigned = in.DebugSigned
	return out
}

// facts turns a resolution into the probe's image set row.
func (s vmImageSet) facts() sandboxvm.ImageSetFacts {
	f := sandboxvm.ImageSetFacts{
		Present: s.res.Reason != sandboximage.ReasonNotInstalled && s.res.Reason != sandboximage.ReasonGuestMissing,
		Version: s.res.Descriptor.Version, GuestUserns: s.res.Descriptor.GuestUserns,
	}
	if s.res.OK {
		f.Verdict = sandboxvm.Verdict{Code: sandboxvm.VerdictAvailable}
		if s.res.Stale {
			f.LastKnownGood = s.res.Descriptor.Version
		}
		return f
	}
	f.Verdict = sandboxvm.Verdict{Code: sandboxvm.VerdictArtifactUnverified, Reason: s.res.Error()}
	return f
}

func init() {
	judge := func(st contentchan.Store, tr contentchan.Trust) string {
		s := loadVMImageSet(st, tr, "", version)
		if s.debugSigned && s.res.Reason != sandboximage.ReasonDebugSet {
			note := "; DEBUG image set (never shipped), signed by the imported debug key"
			if !s.res.OK {
				note += "; " + s.res.Error()
			}
			return note
		}
		return vmRevokedNote(s)
	}
	sandboxContentSetJudges[content.SandboxRootfs] = judge
	sandboxContentSetJudges[content.SandboxGuest] = judge
}

// vmDebugKey reads the recorded debug key: an owner-only regular file
// holding one hex ed25519 public key. Anything else is no key.
func vmDebugKey(store contentchan.Store) ed25519.PublicKey {
	f, err := vmOpenNoFollow(filepath.Join(store.Root, sandboxDebugKeyFile))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !vmDebugKeyOwnerOnly(f) || fi.Size() > 256 {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return nil
	}
	k, err := parseDebugPublicKey(string(b))
	if err != nil {
		return nil
	}
	return k
}

// vmDebugKeyOwnerOnly is the debug key file's owner-only rule, read from
// the handle vmDebugKey opened without following links, so the file judged
// is the file read (WINFIX4 audit finding 5): this user owns it and nobody
// else may read it (fsatomic.FileIsOwnerOnly: the owner uid and no group or
// other bit on POSIX; the token user as owner and a protected DACL allowing
// only that user and SYSTEM on Windows, the one writeSandboxDebugKey gives
// it, RERUN2 D6).
func vmDebugKeyOwnerOnly(f *os.File) bool {
	ok, err := fsatomic.FileIsOwnerOnly(f)
	return err == nil && ok
}

// vmRevokedNote is the content status line's note for a revoked image set:
// it names the revoking manifest and says the set is not available (R-015).
func vmRevokedNote(s vmImageSet) string {
	if s.res.OK || s.res.Reason != sandboximage.ReasonRevoked {
		return ""
	}
	return "; REVOKED, not available: " + s.res.Detail
}

// vmContentStore is the node's sandbox content store.
func vmContentStore(observerDir string) contentchan.Store {
	return contentchan.Store{Root: filepath.Join(observerDir, sandboxContentDir)}
}

// vmImageSetError renders a refusal for a launch.
func vmImageSetError(s vmImageSet) error {
	if s.res.OK {
		return nil
	}
	return fmt.Errorf("terminal_sandbox: cloud-hypervisor: the guest image set is refused: %s", s.res.Error())
}
