package mcprelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// journal.go is the FILE half of the crash-safe launch journal (R8.18 /
// finding-28, doc3 §3.2 mcp_relay_launch_spec): the owner-only verbatim
// backup taken BEFORE a client's config is rewritten, and the hash-verified
// byte-identical restore on disable/uninstall. The journal ROW (client,
// config path, entry key, original launch, config generation, backup path
// + hash, applied digest) is Lane N-M's store; the rewrite itself is the
// per-format writer in internal/mcp, and the SEQUENCE (backup -> row ->
// rewrite; restore rules) is owned by internal/mcprelay/project's
// Projector - the ONE journal owner (parking decision B5). This file holds
// the two file primitives only.
//
// RestoreConfig is the ONE whole-file restore primitive (Sol P3+P4 finding
// 7): it verifies the backup's digest AND, through expectCurrent, that the
// config's CURRENT bytes are the ones the relay wrote (the journal row's
// applied_sha256, node migration 132) - so a config the operator or the
// client edited after the rewrite is never clobbered silently.

// LaunchJournalEntry mirrors one mcp_relay_launch_spec row.
type LaunchJournalEntry struct {
	Client           string
	ConfigPath       string
	EntryKey         string
	OrigCommand      string
	OrigArgs         []string
	OrigCwd          string
	OrigEnvRefs      []string // secret REFERENCES only, never values
	ConfigGeneration int64
	BackupPath       string
	BackupSHA256     string
	AppliedAt        time.Time
	// AppliedSHA256 is the hex SHA-256 of the config bytes the relay WROTE
	// when it applied this row (migration 132). "" = a pre-132 row: the
	// post-rewrite digest is unknown and RestoreConfigCAS refuses the
	// whole-file path (ErrNoAppliedDigest) so the caller falls back to the
	// format-aware reversal of only the relay-owned entry.
	AppliedSHA256 string
}

// Journal errors.
var (
	// ErrBackupMismatch: the backup's bytes no longer hash to the journaled
	// digest; the restore refuses to write anything.
	ErrBackupMismatch = errors.New("mcprelay: launch-journal backup hash mismatch; refusing to restore")
	// ErrConfigChanged: the config file changed since the relay last wrote
	// it (CAS on the current content against the journaled applied digest);
	// a whole-file restore would clobber that edit, so it refuses. The
	// journal row and the backup are retained.
	ErrConfigChanged = errors.New("mcprelay: client config changed since the relay wrote it; refusing the whole-file restore (journal + backup retained)")
	// ErrNoAppliedDigest: the journal row carries no applied_sha256 (a
	// pre-migration-132 row), so the whole-file restore has no CAS target
	// and refuses; the caller reverses only the relay-owned entry instead.
	ErrNoAppliedDigest = errors.New("mcprelay: journal row has no applied digest (pre-132 row); whole-file restore refused")
)

// absentSuffix marks a backup taken of a config that did NOT exist: its
// restore removes the file the rewrite created.
const absentSuffix = ".absent"

// BackupConfig copies configPath's bytes verbatim into an owner-only file
// under backupDir (created 0700) and returns the backup path and the
// SHA-256 of the bytes. A missing config file backs up as zero bytes with
// the "absent" marker so a restore removes the file the rewrite created.
// The bytes are read here; BackupConfigBytes is the same primitive over
// bytes a caller already holds (the staged Before of a projection, so the
// backup is exactly what the writer compared against - no second read).
func BackupConfig(configPath, backupDir string) (backupPath, sha string, err error) {
	raw, rerr := os.ReadFile(configPath)
	absent := false
	if rerr != nil {
		if !errors.Is(rerr, os.ErrNotExist) {
			return "", "", fmt.Errorf("mcprelay.BackupConfig: read %q: %w", configPath, rerr)
		}
		absent = true
		raw = nil
	}
	return BackupConfigBytes(configPath, backupDir, raw, absent)
}

// BackupConfigBytes writes raw (the config's verbatim current bytes, nil /
// absent=true when the file does not exist) to an owner-only backup file
// under backupDir, fsyncs it and its directory (doc3 §12.1 ordering step
// 1), and returns the backup path + hex SHA-256. The name embeds the
// digest, so two backups of identical bytes share one file and a later
// write event of different bytes never overwrites an earlier backup.
func BackupConfigBytes(configPath, backupDir string, raw []byte, absent bool) (backupPath, sha string, err error) {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", "", fmt.Errorf("mcprelay.BackupConfig: %w", err)
	}
	if absent {
		raw = nil
	}
	sha = HashBytes(raw)
	name := filepath.Base(configPath) + "." + sha[:16]
	if absent {
		name += absentSuffix
	}
	backupPath = filepath.Join(backupDir, name+".bak")
	if err := writeAtomic(backupPath, raw, 0o600); err != nil {
		return "", "", fmt.Errorf("mcprelay.BackupConfig: %w", err)
	}
	return backupPath, sha, nil
}

// BackupIsAbsent reports whether backupPath marks a config that did not
// exist when it was backed up (its restore removes the file).
func BackupIsAbsent(backupPath string) bool {
	return filepath.Ext(backupPath) == ".bak" && bytes.HasSuffix([]byte(backupPath), []byte(absentSuffix+".bak"))
}

// RestoreConfig rewrites e.ConfigPath byte-identically from its journaled
// backup after verifying the backup's hash. When expectCurrent is non-nil
// the config's CURRENT bytes must hash to it (the rewrite the journal
// recorded), else ErrConfigChanged - so a config the operator edited by
// hand after the rewrite is never clobbered silently. An `.absent` backup
// removes the file. RestoreConfigCAS is the form every disable/uninstall
// path uses; the nil-expectCurrent form exists for callers that hold no
// applied digest and have verified the current bytes themselves.
func RestoreConfig(e LaunchJournalEntry, expectCurrent *string) error {
	raw, err := os.ReadFile(e.BackupPath)
	if err != nil {
		return fmt.Errorf("mcprelay.RestoreConfig: read backup: %w", err)
	}
	if HashBytes(raw) != e.BackupSHA256 {
		return ErrBackupMismatch
	}
	if expectCurrent != nil {
		cur, err := os.ReadFile(e.ConfigPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("mcprelay.RestoreConfig: read current config: %w", err)
		}
		if HashBytes(cur) != *expectCurrent {
			return fmt.Errorf("%w: %s", ErrConfigChanged, e.ConfigPath)
		}
	}
	if BackupIsAbsent(e.BackupPath) {
		if err := os.Remove(e.ConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("mcprelay.RestoreConfig: remove config: %w", err)
		}
		return nil
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(e.ConfigPath); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeAtomic(e.ConfigPath, raw, mode); err != nil {
		return fmt.Errorf("mcprelay.RestoreConfig: %w", err)
	}
	return nil
}

// RestoreConfigCAS is the whole-file restore every disable / uninstall path
// takes (Sol P3+P4 finding 7): expectCurrent = the row's AppliedSHA256, so
// the file is rewritten only when it still holds exactly the bytes the
// relay wrote. A row without an applied digest (pre-132) is refused with
// ErrNoAppliedDigest; a changed file with ErrConfigChanged; a tampered
// backup with ErrBackupMismatch. In every refusal nothing is written.
func RestoreConfigCAS(e LaunchJournalEntry) error {
	if e.AppliedSHA256 == "" {
		return fmt.Errorf("%w: %s", ErrNoAppliedDigest, e.ConfigPath)
	}
	expect := e.AppliedSHA256
	return RestoreConfig(e, &expect)
}

// HashBytes returns the hex SHA-256 of b (the digest form the journal uses).
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeAtomic writes data to path via a same-directory temp file, fsync,
// rename, directory fsync.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
