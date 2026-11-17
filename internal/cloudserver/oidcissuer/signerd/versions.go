package signerd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// VersionStore is the document signer's durable record of the last version
// it signed per (kind, scope). Commit must be durable before it returns: the
// signer releases a signature only after Commit succeeded, so a restart can
// never sign an equal or older version again.
type VersionStore interface {
	// Last returns the last version committed for (kind, scope), 0 if none.
	Last(kind platformcontract.DocumentKind, scope string) (int64, error)
	// Commit records version as the last for (kind, scope); it refuses a
	// version not above the current one.
	Commit(kind platformcontract.DocumentKind, scope string, version int64) error
}

// versionFileFormat is the version of the on-disk format.
const versionFileFormat = 1

// maxVersionFile bounds the state file read (one entry per org).
const maxVersionFile = 64 << 20

type versionFile struct {
	V        int                         `json:"v"`
	Versions map[string]map[string]int64 `json:"versions"`
}

// FileVersions is a VersionStore in one JSON file, rewritten whole and
// atomically (temporary file, fsync, rename, directory fsync) on every
// commit. It lives in the signer user's state directory (systemd
// StateDirectory=), outside the database's restore domain, which is the
// point: restoring the database cannot roll it back.
type FileVersions struct {
	path  string
	mu    sync.Mutex
	state versionFile
}

// CreateVersionFile writes an empty state file at path (0600, never
// overwriting). The operator runs it once, with `signer document serve
// --init-state`; afterwards a missing file refuses to start, so a lost
// record is noticed rather than silently reset.
func CreateVersionFile(path string) error {
	raw, err := json.Marshal(versionFile{V: versionFileFormat, Versions: map[string]map[string]int64{}})
	if err != nil {
		return fmt.Errorf("signerd.CreateVersionFile: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator-configured state path
	if err != nil {
		return fmt.Errorf("signerd.CreateVersionFile: %w", err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("signerd.CreateVersionFile: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("signerd.CreateVersionFile: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("signerd.CreateVersionFile: %w", err)
	}
	return syncDir(filepath.Dir(path))
}

// OpenFileVersions loads an existing state file and checks every entry.
func OpenFileVersions(path string) (*FileVersions, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("signerd.OpenFileVersions: %w (create it once with --init-state)", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxVersionFile {
		return nil, fmt.Errorf("signerd.OpenFileVersions: %s is not a regular state file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("signerd.OpenFileVersions: %s is accessible by group or others (mode %o)", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator-configured state path
	if err != nil {
		return nil, fmt.Errorf("signerd.OpenFileVersions: %w", err)
	}
	st, err := decodeVersionFile(raw)
	if err != nil {
		return nil, fmt.Errorf("signerd.OpenFileVersions: %w", err)
	}
	return &FileVersions{path: path, state: st}, nil
}

// decodeVersionFile parses and checks a state file's bytes: the format
// version and every entry (a known kind, a scope that fits it, a positive
// version). It is the one reader of the format; OpenFileVersions and
// DecodeVersionRecord both call it.
func decodeVersionFile(raw []byte) (versionFile, error) {
	var st versionFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return versionFile{}, err
	}
	if st.V != versionFileFormat || st.Versions == nil {
		return versionFile{}, fmt.Errorf("format %d, want %d", st.V, versionFileFormat)
	}
	for kind, scopes := range st.Versions {
		for scope, v := range scopes {
			if err := platformcontract.ValidateDocumentScope(platformcontract.DocumentKind(kind), scope); err != nil || v <= 0 {
				return versionFile{}, fmt.Errorf("bad entry %s/%s = %d", kind, scope, v)
			}
		}
	}
	return st, nil
}

// RecordEntry is one (kind, scope) entry of a version record and the last
// version the signer committed for it.
type RecordEntry struct {
	Kind    platformcontract.DocumentKind
	Scope   string
	Version int64
}

// DecodeVersionRecord parses a copy of the signer's state file (the export
// the backup takes, docs/saas-platform-control-plane-runbook.md section 7)
// with the same checks the signer applies at start, and returns its entries
// ordered by kind, then scope. It does not check the file's mode: the
// exported copy is group-readable on purpose. The operator verb
// `observer-cloud signer document raise-floor` reads the record through it
// (managed-SaaS wave 16, W16-D6); nothing writes a record but the signer.
func DecodeVersionRecord(raw []byte) ([]RecordEntry, error) {
	if len(raw) > maxVersionFile {
		return nil, fmt.Errorf("signerd.DecodeVersionRecord: the record is over %d bytes", maxVersionFile)
	}
	st, err := decodeVersionFile(raw)
	if err != nil {
		return nil, fmt.Errorf("signerd.DecodeVersionRecord: %w", err)
	}
	var out []RecordEntry
	for kind, scopes := range st.Versions {
		for scope, v := range scopes {
			out = append(out, RecordEntry{Kind: platformcontract.DocumentKind(kind), Scope: scope, Version: v})
		}
	}
	slices.SortFunc(out, func(a, b RecordEntry) int {
		if c := strings.Compare(string(a.Kind), string(b.Kind)); c != 0 {
			return c
		}
		return strings.Compare(a.Scope, b.Scope)
	})
	return out, nil
}

// Last implements VersionStore.
func (f *FileVersions) Last(kind platformcontract.DocumentKind, scope string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state.Versions[string(kind)][scope], nil
}

// Commit implements VersionStore. The new state is written before it is
// adopted, so a failed write leaves both the file and memory unchanged.
func (f *FileVersions) Commit(kind platformcontract.DocumentKind, scope string, version int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := platformcontract.CheckDocumentVersion(f.state.Versions[string(kind)][scope], version); err != nil {
		return fmt.Errorf("signerd.FileVersions.Commit: %w", err)
	}
	next := versionFile{V: versionFileFormat, Versions: make(map[string]map[string]int64, len(f.state.Versions)+1)}
	for k, scopes := range f.state.Versions {
		cp := make(map[string]int64, len(scopes)+1)
		for s, v := range scopes {
			cp[s] = v
		}
		next.Versions[k] = cp
	}
	if next.Versions[string(kind)] == nil {
		next.Versions[string(kind)] = map[string]int64{}
	}
	next.Versions[string(kind)][scope] = version
	if err := writeFileAtomic(f.path, next); err != nil {
		return fmt.Errorf("signerd.FileVersions.Commit: %w", err)
	}
	f.state = next
	return nil
}

// writeFileAtomic replaces path with v's JSON: a temporary file in the same
// directory, fsync, rename over path, then fsync the directory.
func writeFileAtomic(path string, v versionFile) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".versions-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func(e error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return e
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		return cleanup(err)
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return syncDir(dir)
}

// syncDir fsyncs a directory so a rename in it is durable. Windows cannot
// open a directory for sync; there it is a no-op (the signer runs on Linux).
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) //nolint:gosec // G304: the state file's own directory
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	if err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
