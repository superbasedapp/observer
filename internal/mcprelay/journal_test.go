package mcprelay

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupAndRestoreConfigByteIdentical(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "mcp.json")
	orig := []byte("{\n  \"mcpServers\": {\"gh\": {\"command\": \"npx\", \"args\": [\"-y\",\"gh-mcp\"]}}\n}\r\n\t")
	if err := os.WriteFile(cfg, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	bp, sha, err := BackupConfig(cfg, filepath.Join(dir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "journal")); fi.Mode().Perm() != 0o700 {
		t.Fatalf("journal dir perm %o", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(bp); fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup perm %o", fi.Mode().Perm())
	}
	if sha != HashBytes(orig) {
		t.Fatal("hash mismatch")
	}
	// The rewrite (W4a) replaces the entry; disable restores the ORIGINAL.
	rewritten := []byte(`{"mcpServers":{"gh":{"command":"observer","args":["mcp","relay","--server","gh"]}}}`)
	if err := os.WriteFile(cfg, rewritten, 0o644); err != nil {
		t.Fatal(err)
	}
	e := LaunchJournalEntry{Client: "claude-code", ConfigPath: cfg, EntryKey: "gh", BackupPath: bp, BackupSHA256: sha}
	cur := HashBytes(rewritten)
	if err := RestoreConfig(e, &cur); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfg)
	if string(got) != string(orig) {
		t.Fatalf("restore not byte-identical:\n%q\n%q", got, orig)
	}
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o644 {
		t.Fatalf("restore changed the mode to %o", fi.Mode().Perm())
	}
}

func TestRestoreConfigRefusals(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "mcp.json")
	_ = os.WriteFile(cfg, []byte(`{"a":1}`), 0o600)
	bp, sha, err := BackupConfig(cfg, filepath.Join(dir, "j"))
	if err != nil {
		t.Fatal(err)
	}
	// Tampered backup -> refused, config untouched.
	_ = os.WriteFile(bp, []byte(`{"evil":true}`), 0o600)
	e := LaunchJournalEntry{ConfigPath: cfg, BackupPath: bp, BackupSHA256: sha}
	if err := RestoreConfig(e, nil); !errors.Is(err, ErrBackupMismatch) {
		t.Fatalf("want ErrBackupMismatch, got %v", err)
	}
	if got, _ := os.ReadFile(cfg); string(got) != `{"a":1}` {
		t.Fatal("config clobbered by a refused restore")
	}
	// Hand-edited config after the rewrite -> ErrConfigChanged.
	_ = os.WriteFile(bp, []byte(`{"a":1}`), 0o600)
	_ = os.WriteFile(cfg, []byte(`{"operator":"edited"}`), 0o600)
	expect := HashBytes([]byte(`{"rewritten":true}`))
	if err := RestoreConfig(e, &expect); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("want ErrConfigChanged, got %v", err)
	}
}

func TestBackupAbsentConfigRestoreRemoves(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "absent.json")
	bp, sha, err := BackupConfig(cfg, filepath.Join(dir, "j"))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(cfg, []byte(`{"created":"by rewrite"}`), 0o600)
	if err := RestoreConfig(LaunchJournalEntry{ConfigPath: cfg, BackupPath: bp, BackupSHA256: sha}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("absent-backed config should be removed on restore")
	}
}
