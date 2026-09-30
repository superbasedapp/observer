package orgclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Hardened 0600-file I/O for the agent-access key's file fallback
// (agentaccess_keystore.go). It is deliberately STRICTER than the bearer
// fileStore (bearer_store.go writes with a plain os.WriteFile and reads without
// a mode or owner check): the rules below are the internal/cloudcred fileStore
// posture - the strictest hardened-file pattern in the tree - restated here
// because cloudcred is unexported, forbids internal importers by its purity
// pin, and is zero-egress-pinned to cmd/observer/cloud.go, so orgclient (which
// the daemon links) may not import it.
//
//   - the directory is created 0700 and must be a real directory (not a
//     symlink), owner-only, and owned by this process user (or root);
//   - a write goes to a fresh O_EXCL|O_NOFOLLOW temp file in the SAME
//     directory, is fsynced, then renamed over the destination (atomic: a
//     crash leaves the old key or the new one, never a truncated one);
//   - a read refuses a symlink, a non-regular file, a group/world-accessible
//     mode or a foreign owner, and re-checks the OPEN handle (fstat) so a
//     path swapped between the Lstat and the open is refused too.
//
// The unix build carries the O_NOFOLLOW flag and the POSIX owner check; on
// other platforms agentAccessKeyFileSupported is false and the fallback is
// never selected (the cloudcred FF2 precedent: no verifiable owner/ACL check
// there, so no plaintext key file).

// agentAccessKeyFileMode is the ONLY acceptable permission set for the file.
const agentAccessKeyFileMode fs.FileMode = 0o600

// agentAccessKeyDirMode is the required mode for the key directory.
const agentAccessKeyDirMode fs.FileMode = 0o700

// maxAgentAccessKeyFileBytes caps a read. The largest envelope is an RS256
// PKCS#8 key (~2.4 KB base64); 64 KiB is headroom and still a hard ceiling.
const maxAgentAccessKeyFileBytes = 64 * 1024

// ensureAgentAccessKeyDir creates (0700) and validates the key directory.
func ensureAgentAccessKeyDir(dir string) error {
	if err := os.MkdirAll(dir, agentAccessKeyDirMode); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	li, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat key dir: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("key dir %s is a symlink; refusing", dir)
	}
	if !li.IsDir() {
		return fmt.Errorf("key path %s is not a directory", dir)
	}
	if perm := li.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("key dir %s is mode %#o; it must be 0700", dir, perm)
	}
	return checkAgentAccessKeyOwner(dir, li)
}

// writeAgentAccessKeyFile installs val at path atomically (temp + fsync +
// rename + directory fsync), after validating the directory and any existing
// destination.
func writeAgentAccessKeyFile(path string, val []byte) error {
	dir := filepath.Dir(path)
	if err := ensureAgentAccessKeyDir(dir); err != nil {
		return err
	}
	if li, err := os.Lstat(path); err == nil {
		if li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() {
			return fmt.Errorf("key file %s is not a regular file; refusing to replace it", path)
		}
		if err := checkAgentAccessKeyOwner(path, li); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat key file: %w", err)
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("temp suffix: %w", err)
	}
	tmp := path + ".tmp." + hex.EncodeToString(raw[:])
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|agentAccessKeyOpenNoFollow, agentAccessKeyFileMode)
	if err != nil {
		return fmt.Errorf("create temp key file: %w", err)
	}
	if _, err := f.Write(val); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp key file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync temp key file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp key file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install key file: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// readAgentAccessKeyFile validates and returns the bytes at path; ErrNoSecret
// when the file does not exist.
func readAgentAccessKeyFile(path string) ([]byte, error) {
	li, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSecret
	}
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("key file %s is a symlink; refusing to follow it", path)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	if perm := li.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("key file %s is mode %#o; it must not be group- or world-accessible (chmod 600)", path, perm)
	}
	if err := checkAgentAccessKeyOwner(path, li); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|agentAccessKeyOpenNoFollow, 0)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open key file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s changed under us; refusing to load it", path)
	}
	if err := checkAgentAccessKeyOwner(path, fi); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAgentAccessKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if len(b) > maxAgentAccessKeyFileBytes {
		return nil, fmt.Errorf("key file %s exceeds %d bytes", path, maxAgentAccessKeyFileBytes)
	}
	return b, nil
}
