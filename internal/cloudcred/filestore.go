package cloudcred

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// randomSuffix returns an unpredictable hex suffix for atomic-write temp files,
// so concurrent writers never collide and a temp name cannot be pre-planted.
func randomSuffix() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate temp suffix: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// credFileMode is the ONLY acceptable permission set for a credential file.
const credFileMode fs.FileMode = 0o600

// credDirMode is the required mode for the private credential directory.
const credDirMode fs.FileMode = 0o700

// maxCredBytes caps a single credential read so a hostile oversized "file"
// cannot be slurped unbounded. The largest secret is a base64 Ed25519 private
// key (~88 bytes); WorkOS refresh tokens and API tokens are small. 64 KiB is
// comfortable headroom and still a hard ceiling.
const maxCredBytes = 64 * 1024

// fileStore is the hardened 0600-file fallback. It is intentionally NOT a
// BearerStore fileStore clone: every read and write validates the directory,
// refuses symlinks (Lstat + O_NOFOLLOW), verifies ownership, and writes
// atomically (temp + fsync + rename) so a crash mid-write leaves the previous
// value intact.
//
// host scopes the API token and WorkOS refresh record NAMES (recordName /
// scopedRecords) — never the directory, so a host-scoped and a legacy
// unscoped store over the same dir see each other's device key file (shared)
// but distinct token/refresh files. host == "" reproduces the legacy
// single-slot behaviour.
type fileStore struct {
	dir  string
	host string
}

func (s *fileStore) Backend() string { return "file" }

// SecurityDiagnostic reports the degraded posture of the file fallback: the
// bytes are protected only by filesystem permissions, not OS-backed encryption.
func (s *fileStore) SecurityDiagnostic() string {
	return "cloud credentials are stored in 0600 files at " + s.dir +
		" WITHOUT OS-backed encryption (the OS keychain was unavailable); " +
		"protection relies on filesystem permissions and ownership only"
}

func (s *fileStore) path(rec string) string {
	return filepath.Join(s.dir, ServiceName+"."+rec)
}

func (s *fileStore) SaveWorkOSRefresh(refresh string) error {
	return withCredentialLock(s.dir, func() error { return s.write(recordName(recWorkOSRefresh, s.host), []byte(refresh)) })
}

func (s *fileStore) LoadWorkOSRefresh() (string, error) {
	b, err := s.readScoped(recWorkOSRefresh)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *fileStore) SaveAPIToken(token string) error {
	return withCredentialLock(s.dir, func() error { return s.write(recordName(recAPIToken, s.host), []byte(token)) })
}

func (s *fileStore) LoadAPIToken() (string, error) {
	b, err := s.readScoped(recAPIToken)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *fileStore) SaveDeviceKey(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("cloudcred.SaveDeviceKey: key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	// recordName never scopes recDeviceKey: one device identity is shared
	// across every host.
	return s.write(recordName(recDeviceKey, s.host), []byte(base64.StdEncoding.EncodeToString(key)))
}

func (s *fileStore) LoadDeviceKey() (ed25519.PrivateKey, error) {
	b, err := s.read(recordName(recDeviceKey, s.host))
	if err != nil {
		return nil, err
	}
	return decodeDeviceKey(string(b))
}

// readScoped loads rec scoped to s.host, with the one-time legacy adoption
// documented on OpenForHost: when the scoped file is absent, a live legacy
// (unscoped) file is returned AND migrated — written under the scoped name,
// then the legacy file removed — so no later reader (a different host)
// adopts it again.
func (s *fileStore) readScoped(rec string) ([]byte, error) {
	scoped := recordName(rec, s.host)
	b, err := s.read(scoped)
	if err == nil {
		return b, nil
	}
	if !errors.Is(err, ErrNotFound) || s.host == "" || !scopedRecords[rec] {
		return nil, err
	}
	err = adoptLegacyBundle(s.dir, s.host,
		func(rec string) (string, error) { b, err := s.read(rec); return string(b), err },
		func(rec, value string) error { return s.write(rec, []byte(value)) },
		func(rec string) error { return os.Remove(s.path(rec)) })
	if err != nil {
		return nil, err
	}
	return s.read(scoped)
}

// Clear removes this host's scoped API token and WorkOS refresh files, the
// legacy unscoped files if still present, and the device signing key file.
// The device key is shared across hosts, so Clear is a full device reset
// (logout / device-revoke) — it does not reference-count hosts, and clearing
// one host's store clears the device identity for every host.
func (s *fileStore) Clear() error {
	return withCredentialLock(s.dir, s.clearLocked)
}

func (s *fileStore) clearLocked() error {
	recs := []string{recDeviceKey, recWorkOSRefresh, recAPIToken}
	if s.host != "" {
		recs = append(recs, recordName(recWorkOSRefresh, s.host), recordName(recAPIToken, s.host))
	} else {
		// A host-less Clear (`observer cloud logout` with no base URL resolvable)
		// is the full local wipe: every host's scoped record goes too. The
		// directory is dedicated to this service, so every file carrying the
		// service prefix is ours to remove; the keychain-unavailable sentinel
		// has no such prefix and stays.
		if entries, err := os.ReadDir(s.dir); err == nil {
			for _, e := range entries {
				if name := e.Name(); strings.HasPrefix(name, ServiceName+".") && name != ServiceName+".coordination-lock" && name != ServiceName+"."+recLegacyHost {
					recs = append(recs, strings.TrimPrefix(name, ServiceName+"."))
				}
			}
		}
	}
	var errs []error
	for _, rec := range recs {
		if err := os.Remove(s.path(rec)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cloudcred.fileStore.Clear: %w", errors.Join(errs...))
	}
	return nil
}

// ensureDir creates (0700) and validates the private credential directory: it
// must be a real directory (not a symlink), owner-only, and owned by us. A
// world/group-accessible or foreign-owned directory means someone else can
// control the files we are about to trust, so we refuse.
func (s *fileStore) ensureDir() error {
	if err := os.MkdirAll(s.dir, credDirMode); err != nil {
		return fmt.Errorf("cloudcred: create credential dir: %w", err)
	}
	li, err := os.Lstat(s.dir)
	if err != nil {
		return fmt.Errorf("cloudcred: stat credential dir: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("cloudcred: credential dir %s is a symlink; refusing", s.dir)
	}
	if !li.IsDir() {
		return fmt.Errorf("cloudcred: credential path %s is not a directory", s.dir)
	}
	if perm := li.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("cloudcred: credential dir %s is mode %#o; must be 0700", s.dir, perm)
	}
	if err := checkOwner(s.dir, li); err != nil {
		return err
	}
	return nil
}

// write installs val at rec atomically. The bytes go to a fresh O_EXCL temp
// file in the SAME directory, are fsynced, and only then rename over the
// destination; the parent directory is fsynced so the rename is durable. A
// crash at any point leaves either the old file or the new one, never a
// truncated one.
func (s *fileStore) write(rec string, val []byte) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	dst := s.path(rec)
	// If a destination already exists, validate it is safe to replace (not a
	// symlink pointing elsewhere, not foreign-owned) before we touch it.
	if err := s.validateExistingTarget(dst); err != nil {
		return err
	}
	// A UNIQUE temp name per write lets concurrent rotations of the same record
	// proceed without colliding on the O_EXCL create; the last rename wins and
	// the old value stays readable throughout.
	suffix, err := randomSuffix()
	if err != nil {
		return fmt.Errorf("cloudcred: %w", err)
	}
	tmp := dst + ".tmp." + suffix
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|openNoFollow, credFileMode)
	if err != nil {
		return fmt.Errorf("cloudcred: create temp credential file: %w", err)
	}
	if _, err := f.Write(val); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("cloudcred: write temp credential file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("cloudcred: fsync temp credential file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cloudcred: close temp credential file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cloudcred: install credential file: %w", err)
	}
	s.syncDir()
	return nil
}

// validateExistingTarget refuses to overwrite a destination that has been
// swapped for a symlink or reassigned to another owner since it was written.
func (s *fileStore) validateExistingTarget(dst string) error {
	li, err := os.Lstat(dst)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cloudcred: stat credential file: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("cloudcred: credential file %s is a symlink; refusing to replace it", dst)
	}
	if !li.Mode().IsRegular() {
		return fmt.Errorf("cloudcred: credential file %s is not a regular file", dst)
	}
	return checkOwner(dst, li)
}

// syncDir best-effort fsyncs the credential directory so the rename is durable.
// A directory that cannot be opened for sync (some platforms) is not fatal.
func (s *fileStore) syncDir() {
	d, err := os.Open(s.dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// read validates and returns the bytes at rec. It refuses a symlink (Lstat +
// O_NOFOLLOW), a group/world-accessible mode, a foreign owner, and re-checks
// the OPEN handle to close the TOCTOU window a path-only check would leave.
func (s *fileStore) read(rec string) ([]byte, error) {
	path := s.path(rec)
	li, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cloudcred: stat credential file: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("cloudcred: credential file %s is a symlink; refusing to follow it", path)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("cloudcred: credential file %s is not a regular file", path)
	}
	if perm := li.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("cloudcred: credential file %s is mode %#o; it must not be group- or world-accessible (chmod 600)", path, perm)
	}
	if err := checkOwner(path, li); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		return nil, fmt.Errorf("cloudcred: open credential file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Re-validate the OPEN handle: the path could have been swapped between the
	// Lstat and the open.
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cloudcred: stat open credential file: %w", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("cloudcred: credential file %s changed under us; refusing to load it", path)
	}
	if err := checkOwnerFile(path, f, fi); err != nil {
		return nil, err
	}

	buf := make([]byte, maxCredBytes+1)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("cloudcred: read credential file: %w", err)
	}
	if n > maxCredBytes {
		return nil, fmt.Errorf("cloudcred: credential file %s exceeds %d bytes", path, maxCredBytes)
	}
	return buf[:n], nil
}
