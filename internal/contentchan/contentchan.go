package contentchan

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// File names inside a kind's directory.
const (
	ManifestFile = "manifest.json"
	StateFile    = "state.json"
)

// maxStateBytes caps state.json.
const maxStateBytes = 64 << 10

// Trust is the key material a verification uses.
type Trust struct {
	// VendorKeys are the accepted vendor keys (the caller passes the set
	// compiled into the agent); none verifies nothing.
	VendorKeys []ed25519.PublicKey
	// FeedKeys are the accepted content-feed keys
	// (internal/update.ContentFeedPublicKeys). content.Verify accepts them
	// only for a feed-signed envelope of a ClassFeed kind; none means a
	// feed-signed set verifies nowhere (fail closed).
	FeedKeys []ed25519.PublicKey
	// RequireOrg and OrgKey: a managed node accepts only countersigned
	// content from its org mirror.
	RequireOrg bool
	OrgKey     ed25519.PublicKey
}

// Store is one content root.
type Store struct {
	Root string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// GOOS and GOARCH select platform entries; empty means this build's.
	GOOS, GOARCH string
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// platformFor is the platform kind's entries are selected for: the kind's
// target OS (content.PlatformFor) on this store's platform.
func (s Store) platformFor(kind content.Kind) (string, string) {
	goos, goarch := s.GOOS, s.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return content.PlatformFor(kind, goos, goarch)
}

// errNoEntryApplies judges a manifest none of whose entries this store's
// walk selects. Before, such a set installed nothing and reported success,
// so its files were never checked (a tampered guest set was accepted on
// Windows, 2026-10-25): an entry the walk cannot match is refused, never
// skipped into an empty install. A kind whose manifest is itself the
// content (content.KindSpec.ManifestIsContent, the engine pins) differs in
// two rows (WINFIX4 audit finding 6): a manifest that carries a revocation
// installs, so the revocation reaches every node, and keepOthers says the
// install removes only the revoked bytes; one that carries none is refused
// as not_covered_here, so the node keeps its last good manifest and its
// engine bytes (before, it installed empty and pruned them).
func errNoEntryApplies(kind content.Kind, m content.Manifest, goos, goarch string) (keepOthers bool, err error) {
	if spec, ok := content.KindOf(kind); ok && spec.ManifestIsContent {
		if len(m.Revoked) > 0 {
			return true, nil
		}
		return false, &content.Refusal{Reason: content.ContentReasonNotCoveredHere, Detail: "the manifest names no entry for " + goos + "/" + goarch + " and revokes nothing; the last good one stays"}
	}
	return false, &content.Refusal{Reason: content.ContentReasonNotCovered, Detail: "no entry of the manifest applies to " + goos + "/" + goarch}
}

// KindDir is a kind's directory.
func (s Store) KindDir(kind content.Kind) (string, error) {
	if _, ok := content.KindOf(kind); !ok || s.Root == "" {
		return "", fmt.Errorf("contentchan: unknown kind %q or no root", kind)
	}
	return filepath.Join(s.Root, string(kind)), nil
}

// State reads a kind's state; a kind never installed has the zero state.
func (s Store) State(kind content.Kind) (content.State, error) {
	dir, err := s.KindDir(kind)
	if err != nil {
		return content.State{}, err
	}
	b, err := readCapped(filepath.Join(dir, StateFile), maxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return content.State{Kind: kind}, nil
	}
	if err != nil {
		return content.State{}, fmt.Errorf("contentchan.State: %w", err)
	}
	var st content.State
	if err := json.Unmarshal(b, &st); err != nil {
		return content.State{}, fmt.Errorf("contentchan.State: %w", err)
	}
	return st, nil
}

// Install verifies envelope as kind against the kind's accepted high-water
// mark, checks every artifact the manifest covers for this platform
// against its entry, and only then writes the artifacts, the envelope and
// the state. artifacts maps entry names to bytes; an entry for this
// platform with no bytes is a refusal (not_covered), so a half update is
// never installed. On any refusal the last-known-good stays and the state
// records the reason; the refusal is returned.
func (s Store) Install(kind content.Kind, envelope []byte, artifacts map[string][]byte, tr Trust) (content.State, error) {
	dir, err := s.KindDir(kind)
	if err != nil {
		return content.State{}, err
	}
	prev, err := s.State(kind)
	if err != nil {
		// An unreadable state is a corrupt install: start over from no
		// high-water mark only after the operator removes it.
		return content.State{}, err
	}
	now := s.now()
	res, verr := content.Verify(content.VerifyInput{
		Envelope: envelope, Kind: kind, VendorKeys: tr.VendorKeys, FeedKeys: tr.FeedKeys,
		RequireOrg: tr.RequireOrg, OrgKey: tr.OrgKey, Accepted: prev.Accepted, Now: now,
	})
	var write map[string][]byte
	keepOthers := false
	if verr == nil {
		write, keepOthers, verr = s.selectArtifacts(kind, res.Manifest, artifacts)
	}
	if verr != nil {
		next := content.Apply(prev, content.Result{}, verr, now)
		_ = s.writeState(dir, next)
		return next, verr
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return prev, fmt.Errorf("contentchan.Install: %w", err)
	}
	for name, b := range write {
		if err := writeAtomic(filepath.Join(dir, name), b); err != nil {
			return prev, fmt.Errorf("contentchan.Install: %w", err)
		}
	}
	if err := writeAtomic(filepath.Join(dir, ManifestFile), envelope); err != nil {
		return prev, fmt.Errorf("contentchan.Install: %w", err)
	}
	next := content.Apply(prev, res, nil, now)
	if err := s.writeState(dir, next); err != nil {
		return prev, err
	}
	if keepOthers {
		pruneRevoked(dir, res.Manifest)
	} else {
		s.prune(dir, write)
	}
	return next, nil
}

// selectArtifacts returns the bytes to write: every entry for this platform,
// each checked against its digest, and whether the install keeps the
// files already there except the revoked ones (errNoEntryApplies).
func (s Store) selectArtifacts(kind content.Kind, m content.Manifest, artifacts map[string][]byte) (map[string][]byte, bool, error) {
	goos, goarch := s.platformFor(kind)
	// A set partial for this platform is refused before anything is
	// written (WINFIX2 audit finding 8).
	if err := content.CheckCompleteSet(m, goos, goarch); err != nil {
		return nil, false, err
	}
	out := map[string][]byte{}
	applied := 0
	for _, e := range m.Entries {
		if !content.EntryApplies(e, goos, goarch) {
			continue
		}
		applied++
		if e.Name == ManifestFile || e.Name == StateFile {
			return nil, false, &content.Refusal{Reason: content.ContentReasonStructure, Detail: "entry name collides with a channel file"}
		}
		if content.IsRevoked(m, e.SHA256) {
			continue
		}
		b, ok := artifacts[e.Name]
		if !ok {
			return nil, false, &content.Refusal{Reason: content.ContentReasonNotCovered, Detail: "no bytes for " + e.Name}
		}
		if err := content.CheckArtifact(e, b); err != nil {
			return nil, false, err
		}
		out[e.Name] = b
	}
	if applied == 0 && len(m.Entries) > 0 {
		keep, err := errNoEntryApplies(kind, m, goos, goarch)
		if err != nil {
			return nil, false, err
		}
		return out, keep, nil
	}
	return out, false, nil
}

// pruneRevoked removes the files in dir whose digest m revokes, and
// nothing else: a manifest that covers no entry of this platform but
// revokes a digest reaches the node without taking its unrevoked bytes
// (WINFIX4 audit finding 6).
func pruneRevoked(dir string, m content.Manifest) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if n == ManifestFile || n == StateFile || !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, n)
		if sum, ok := fileSHA256(p); ok && content.IsRevoked(m, sum) {
			_ = os.Remove(p)
		}
	}
}

// fileSHA256 is a regular file's sha256 (false when it cannot be read).
func fileSHA256(p string) (string, bool) {
	f, err := os.Open(p) //nolint:gosec // G304: a file of the kind's own directory
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// prune removes files the new manifest no longer covers.
func (s Store) prune(dir string, keep map[string][]byte) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if n == ManifestFile || n == StateFile || keep[n] != nil || e.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(dir, n))
	}
}

func (s Store) writeState(dir string, st content.State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("contentchan: %w", err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("contentchan: %w", err)
	}
	return writeAtomic(filepath.Join(dir, StateFile), b)
}

// Loaded is an accepted kind, re-verified.
type Loaded struct {
	Manifest  content.Manifest
	State     content.State
	Freshness content.Freshness
	dir       string
	goos      string
	goarch    string
}

// ErrNotInstalled is Load's answer for a kind with nothing accepted.
var ErrNotInstalled = errors.New("contentchan: nothing installed for this kind")

// Load re-verifies the accepted envelope (signature, structure, ordering
// against its own state; expiry is judged by Freshness, not refused) and
// returns it with its freshness under floor (0 is the kind's floor). Any
// failure is an error: the caller treats the data as unknown.
func (s Store) Load(kind content.Kind, tr Trust, floor time.Duration) (Loaded, error) {
	dir, err := s.KindDir(kind)
	if err != nil {
		return Loaded{}, err
	}
	st, err := s.State(kind)
	if err != nil {
		return Loaded{}, err
	}
	if st.Accepted == nil {
		return Loaded{}, ErrNotInstalled
	}
	env, err := readCapped(filepath.Join(dir, ManifestFile), content.MaxEnvelopeBytes)
	if err != nil {
		return Loaded{}, fmt.Errorf("contentchan.Load: %w", err)
	}
	now := s.now()
	res, err := content.Verify(content.VerifyInput{
		Envelope: env, Kind: kind, VendorKeys: tr.VendorKeys, FeedKeys: tr.FeedKeys, RequireOrg: tr.RequireOrg, OrgKey: tr.OrgKey,
		Accepted: st.Accepted, Now: now, AllowExpired: true,
	})
	if err != nil {
		return Loaded{}, err
	}
	if res.Hash != st.Accepted.ManifestHash {
		return Loaded{}, &content.Refusal{Reason: content.ContentReasonFork, Detail: "the envelope on disk is not the accepted one"}
	}
	goos, goarch := s.platformFor(kind)
	// An accepted set partial for this platform (installed by a build
	// before the check) is refused at load too.
	if err := content.CheckCompleteSet(res.Manifest, goos, goarch); err != nil {
		return Loaded{}, err
	}
	return Loaded{
		Manifest: res.Manifest, State: st, Freshness: content.FreshnessAt(res.Manifest, now, floor),
		dir: dir, goos: goos, goarch: goarch,
	}, nil
}

// ReadArtifact reads one covered artifact, capped at its size, and checks
// its digest on every read: a file changed after install is refused.
func (l Loaded) ReadArtifact(name string) ([]byte, error) {
	e, err := content.EntryFor(l.Manifest, name, l.goos, l.goarch)
	if err != nil {
		return nil, err
	}
	b, err := readCapped(filepath.Join(l.dir, e.Name), e.SizeBytes)
	if err != nil {
		return nil, fmt.Errorf("contentchan.ReadArtifact: %w", err)
	}
	if err := content.CheckArtifact(e, b); err != nil {
		return nil, err
	}
	return b, nil
}

// errTooLarge is readCapped's refusal.
var errTooLarge = errors.New("contentchan: file over its cap")

// readCapped reads at most limit bytes and refuses a longer file. It does
// not follow a symlink at the final element.
func readCapped(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("contentchan: %s is not a regular file", filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errTooLarge
	}
	return b, nil
}

// writeAtomic writes path through a temporary file and a rename, 0600.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// InstallFiles is Install for artifacts already on disk (files maps entry
// names to paths), for kinds too large to hold in memory (the OSV exports):
// the same verification against the kind's high-water mark, every covered
// artifact checked for its exact size and digest while it is read, and
// nothing written unless all of them match. Each verified file is moved
// into the kind's directory (renamed when it is on the same filesystem,
// else copied); the caller's files are consumed either way.
func (s Store) InstallFiles(kind content.Kind, envelope []byte, files map[string]string, tr Trust) (content.State, error) {
	dir, err := s.KindDir(kind)
	if err != nil {
		return content.State{}, err
	}
	prev, err := s.State(kind)
	if err != nil {
		return content.State{}, err
	}
	now := s.now()
	res, verr := content.Verify(content.VerifyInput{
		Envelope: envelope, Kind: kind, VendorKeys: tr.VendorKeys, FeedKeys: tr.FeedKeys,
		RequireOrg: tr.RequireOrg, OrgKey: tr.OrgKey, Accepted: prev.Accepted, Now: now,
	})
	var write map[string]string
	keepOthers := false
	if verr == nil {
		write, keepOthers, verr = s.selectFiles(kind, res.Manifest, files)
	}
	if verr != nil {
		next := content.Apply(prev, content.Result{}, verr, now)
		_ = s.writeState(dir, next)
		return next, verr
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return prev, fmt.Errorf("contentchan.InstallFiles: %w", err)
	}
	keep := map[string][]byte{}
	for name, src := range write {
		if err := moveInto(src, filepath.Join(dir, name)); err != nil {
			return prev, fmt.Errorf("contentchan.InstallFiles: %w", err)
		}
		keep[name] = []byte{1}
	}
	if err := writeAtomic(filepath.Join(dir, ManifestFile), envelope); err != nil {
		return prev, fmt.Errorf("contentchan.InstallFiles: %w", err)
	}
	next := content.Apply(prev, res, nil, now)
	if err := s.writeState(dir, next); err != nil {
		return prev, err
	}
	if keepOthers {
		pruneRevoked(dir, res.Manifest)
	} else {
		s.prune(dir, keep)
	}
	return next, nil
}

// selectFiles is selectArtifacts over files on disk, hashing each one.
func (s Store) selectFiles(kind content.Kind, m content.Manifest, files map[string]string) (map[string]string, bool, error) {
	goos, goarch := s.platformFor(kind)
	// A set partial for this platform is refused before anything is
	// written (WINFIX2 audit finding 8).
	if err := content.CheckCompleteSet(m, goos, goarch); err != nil {
		return nil, false, err
	}
	out := map[string]string{}
	applied := 0
	for _, e := range m.Entries {
		if !content.EntryApplies(e, goos, goarch) {
			continue
		}
		applied++
		if e.Name == ManifestFile || e.Name == StateFile {
			return nil, false, &content.Refusal{Reason: content.ContentReasonStructure, Detail: "entry name collides with a channel file"}
		}
		if content.IsRevoked(m, e.SHA256) {
			continue
		}
		p, ok := files[e.Name]
		if !ok {
			return nil, false, &content.Refusal{Reason: content.ContentReasonNotCovered, Detail: "no bytes for " + e.Name}
		}
		if err := checkFile(e, p); err != nil {
			return nil, false, err
		}
		out[e.Name] = p
	}
	if applied == 0 && len(m.Entries) > 0 {
		keep, err := errNoEntryApplies(kind, m, goos, goarch)
		if err != nil {
			return nil, false, err
		}
		return out, keep, nil
	}
	return out, false, nil
}

// checkFile verifies a file against an entry: a regular file of exactly
// the entry's size whose sha256 is the entry's digest.
func checkFile(e content.Entry, path string) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != e.SizeBytes {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " is not a regular file of the listed size"}
	}
	f, err := os.Open(path)
	if err != nil {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " cannot be read"}
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, e.SizeBytes+1)); err != nil {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " cannot be read"}
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(e.SHA256) {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: e.Name + " does not match its digest"}
	}
	return nil
}

// moveInto moves src to dst (0600): a rename, or a copy and a removal
// across filesystems.
func moveInto(src, dst string) error {
	if err := os.Chmod(src, 0o600); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-"+filepath.Base(dst)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, dst); err != nil {
		_ = os.Remove(name)
		return err
	}
	_ = os.Remove(src)
	return nil
}

// InstalledArtifact returns the path of the file installed in kind's
// directory under e's name when e applies to this store's platform for kind
// and that file is a regular file of exactly e's size whose sha256 is e's
// digest; ok is false otherwise (nothing installed, another version, a
// changed file, an entry name that is not a plain file name). A fetch of a
// new manifest reuses such a file instead of downloading the same bytes
// again (internal/orgclient's org mirror fetch); InstallFiles still checks
// it like any other file.
func (s Store) InstalledArtifact(kind content.Kind, e content.Entry) (path string, ok bool) {
	dir, err := s.KindDir(kind)
	if err != nil || e.Name == "" || e.Name == "." || e.Name == ".." || e.Name == ManifestFile || e.Name == StateFile || strings.ContainsAny(e.Name, `/\`) {
		return "", false
	}
	goos, goarch := s.platformFor(kind)
	if !content.EntryApplies(e, goos, goarch) {
		return "", false
	}
	p := filepath.Join(dir, e.Name)
	if checkFile(e, p) != nil {
		return "", false
	}
	return p, true
}

// ArtifactPath returns the on-disk path of a covered artifact, after
// checking its size (not its digest: a caller that streams it, the OSV
// export reader, checks the digest as it reads).
func (l Loaded) ArtifactPath(name string) (string, content.Entry, error) {
	e, err := content.EntryFor(l.Manifest, name, l.goos, l.goarch)
	if err != nil {
		return "", content.Entry{}, err
	}
	p := filepath.Join(l.dir, e.Name)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != e.SizeBytes {
		return "", content.Entry{}, &content.Refusal{Reason: content.ContentReasonArtifact, Detail: name + " is missing or changed"}
	}
	return p, e, nil
}
