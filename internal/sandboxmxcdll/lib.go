package sandboxmxcdll

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// Library is the loaded mxc_ffi C ABI, the four calls this driver makes.
type Library interface {
	// Version is mxc_version(): the library's own version string.
	Version() string
	// ProbeRequest is mxc_probe_request_json_with_error over a config
	// document: MXC's tier choice for that policy, without creating
	// anything. A native failure is a *NativeError.
	ProbeRequest(doc []byte) ([]byte, error)
	// RunOneShot is mxc_run_json: it creates the container the document
	// describes, runs its command to completion and closes it (the
	// create-and-close check).
	RunOneShot(doc []byte) (RunResult, error)
	// Close unloads the library.
	Close() error
}

// RunResult is mxc_run_json's MxcRunResult, decoded.
type RunResult struct {
	Status   int
	ExitCode int
	TimedOut bool
	Error    *NativeError
	Warnings string
	// Stdout is the captured output, capped at MaxCapturedOutput.
	Stdout string
}

// MaxCapturedOutput caps the captured output of a one-shot run.
const MaxCapturedOutput = 4096

// Stage is how far Gather goes (the live checks stop early; the daemon's
// probe always runs to StageCreate).
type Stage int

// The stages, in order.
const (
	// StageCreate runs every row, the create-and-close check included.
	StageCreate Stage = iota
	// StageVersion stops after the library version is read.
	StageVersion
	// StageRequest stops after MXC's request probe (nothing is created).
	StageRequest
)

// NativeError is an MxcErrorDetail with the call's status.
type NativeError struct {
	Status      int
	Message     string
	Operation   string
	NativeCode  string
	Remediation string
}

// Error renders the detail the way MXC's SDKs do: the status's code name,
// then the message.
func (e *NativeError) Error() string {
	s := StatusName(e.Status)
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.NativeCode != "" {
		s += " (" + e.NativeCode + ")"
	}
	return s
}

// StatusName maps an MXC_STATUS_* value to its code (the SDK's table).
func StatusName(status int) string {
	switch status {
	case 0:
		return "success"
	case 1, 100, 101:
		return "malformed_request"
	case 2:
		return "unsupported_containment"
	case 3:
		return "unsupported_phase"
	case 4:
		return "backend_unavailable"
	case 11:
		return "policy_validation"
	}
	return "backend_error"
}

// HeldFile is a bundled file opened for reading with writers denied for as
// long as it is held.
type HeldFile interface {
	io.Reader
	Close() error
}

// Env is the injected I/O of Gather.
type Env struct {
	// Windows and Active are the ladder's first two facts.
	Windows bool
	Active  bool
	// Build returns the OS build, its update build revision and edition.
	Build func() (build, ubr int, edition string)
	// Dir is where the bundled files are installed
	// (<observer.exe dir>\mxc).
	Dir string
	// Manifest is the pinned set for this architecture; ok=false when this
	// build pins none (every file then counts as missing).
	Manifest     sandboxmxc.Manifest
	HasPinnedSet bool
	// Open opens a file denying writers (and refusing a link or reparse
	// point).
	Open func(path string) (HeldFile, error)
	// Verify checks the Authenticode signature of a held file at path.
	Verify func(path string, f HeldFile) error
	// Load loads the library from the held file at path.
	Load func(path string, f HeldFile) (Library, error)
	// ProbeDoc and CheckDoc are the documents the request probe and the
	// create-and-close check send (sandboxmxc.ProbeDocument, encoded).
	ProbeDoc []byte
	CheckDoc []byte
	// Stage is how far to go (zero: every row).
	Stage Stage
}

// Verified is what Gather leaves open for a caller that goes on to use the
// files (the run helper): the held files and the loaded library. Release
// closes them all.
type Verified struct {
	Library Library
	held    []HeldFile
	paths   map[string]string
}

// Path is the verified path of a bundled file.
func (v *Verified) Path(name string) string {
	if v == nil {
		return ""
	}
	return v.paths[name]
}

// Release unloads the library and closes every held file.
func (v *Verified) Release() {
	if v == nil {
		return
	}
	if v.Library != nil {
		_ = v.Library.Close()
		v.Library = nil
	}
	for _, f := range v.held {
		_ = f.Close()
	}
	v.held = nil
}

// ErrNotVerified is returned by Gather's caller-facing helpers when the
// ladder refused.
var ErrNotVerified = errors.New("sandboxmxcdll: the MXC files did not verify")

// Gather fills the ladder's facts in order and stops at the first gap. It
// returns the facts and, when every file verified and the library loaded,
// the held files and the library (the caller releases them). keepOpen
// false releases everything before returning (the probe helper).
func Gather(env Env, keepOpen bool) (sandboxmxc.HostFacts, *Verified) {
	f := sandboxmxc.HostFacts{Windows: env.Windows, Active: env.Active}
	if !env.Windows || !env.Active {
		return f, nil
	}
	if env.Build != nil {
		f.Build, f.UBR, f.Edition = env.Build()
	}
	if !sandboxmxc.CheckBuild(f.Build, f.UBR).OK() {
		return f, nil
	}
	v := &Verified{paths: map[string]string{}}
	ok := env.HasPinnedSet
	if ok {
		for _, want := range env.Manifest.Files {
			ff, hf := checkFile(env, want)
			f.Files = append(f.Files, ff)
			if hf != nil {
				v.held = append(v.held, hf)
				v.paths[want.Name] = filepath.Join(env.Dir, want.Name)
			}
			// Every file is still read (so the ladder names the first gap in
			// manifest order), but a tampered file is never verified and
			// nothing is loaded.
			if !ff.Present || !ff.Signed || !hashEqual(ff.SHA256, want.SHA256) {
				ok = false
			}
		}
	}
	if !ok {
		v.Release()
		return f, nil
	}
	if env.Load == nil {
		f.LibraryError = "no loader on this platform"
		v.Release()
		return f, nil
	}
	ffiPath := v.paths[sandboxmxc.FileFFI]
	lib, err := env.Load(ffiPath, v.heldFor(env, sandboxmxc.FileFFI))
	if err != nil {
		f.LibraryError = err.Error()
		v.Release()
		return f, nil
	}
	v.Library = lib
	f.LibraryVersion = lib.Version()
	if env.Stage == StageVersion || sandboxmxc.CheckVersion(f.LibraryVersion, sandboxmxc.Pins) == sandboxmxc.VersionUntested {
		v.Release()
		return f, nil
	}
	out, err := lib.ProbeRequest(env.ProbeDoc)
	if err != nil {
		f.ProbeError = err.Error()
		v.Release()
		return f, nil
	}
	f.ProbeJSON = string(out)
	if r := sandboxmxc.Probe(f, env.Manifest); r.Rule != "create_close" || env.Stage == StageRequest {
		// The request probe refused (or the answer did not parse): no
		// container is created on a host MXC already declined.
		v.Release()
		return f, nil
	}
	cc := &sandboxmxc.CreateClose{Ran: true}
	res, err := lib.RunOneShot(env.CheckDoc)
	switch {
	case err != nil:
		cc.Status, cc.Error = -1, err.Error()
	default:
		cc.Status, cc.ExitCode, cc.TimedOut = res.Status, res.ExitCode, res.TimedOut
		if res.Error != nil {
			cc.Error = res.Error.Error()
		}
	}
	f.CreateClose = cc
	if !keepOpen || !sandboxmxc.Probe(f, env.Manifest).Verdict.OK() {
		v.Release()
		return f, nil
	}
	return f, v
}

// heldFor is the held handle of a bundled file (the files are appended in
// manifest order).
func (v *Verified) heldFor(env Env, name string) HeldFile {
	for i, want := range env.Manifest.Files {
		if want.Name == name && i < len(v.held) {
			return v.held[i]
		}
	}
	return nil
}

// checkFile opens, hashes and verifies one file. The handle stays open
// (returned) when the file opened, so the caller holds it.
func checkFile(env Env, want sandboxmxc.BundledFile) (sandboxmxc.FileFact, HeldFile) {
	ff := sandboxmxc.FileFact{Name: want.Name}
	if env.Open == nil || env.Dir == "" {
		return ff, nil
	}
	path := filepath.Join(env.Dir, want.Name)
	hf, err := env.Open(path)
	if err != nil {
		return ff, nil
	}
	ff.Present = true
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(hf, want.Size+1))
	if err != nil || n != want.Size {
		ff.SHA256 = fmt.Sprintf("size-%d", n)
		return ff, hf
	}
	ff.SHA256 = hex.EncodeToString(h.Sum(nil))
	if !hashEqual(ff.SHA256, want.SHA256) {
		return ff, hf
	}
	ff.SignatureChecked = env.Verify != nil
	if env.Verify != nil {
		if err := env.Verify(path, hf); err != nil {
			ff.SignatureError = err.Error()
		} else {
			ff.Signed = true
		}
	}
	return ff, hf
}

func hashEqual(a, b string) bool { return len(a) == 64 && a == b }
